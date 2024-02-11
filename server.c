#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 8096
#define SRV_DIRECTORY "./html"
#define PORT 2728

struct {
    char *ext;
    char *filetype;
} extensions[] = {
    {"css", "text/css"},
    {"gif", "image/gif"},
    {"jpg", "image/jpg"},
    {"jpeg", "image/jpeg"},
    {"png", "image/png"},
    {"ico", "image/ico"},
    {"zip", "image/zip"},
    {"gz", "image/gz"},
    {"tar", "image/tar"},
    {"htm", "text/html"},
    {"html", "text/html"},
    {0, 0}
};

void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void web(int fd, int hit) {
    int j, file_fd, buflen;
    long i, ret, len;
    char *fstr;
    static char buffer[BUFSIZE + 1]; /* static so zero filled */

    ret = read(fd, buffer, BUFSIZE); /* read Web request in one go */
    if (ret <= 0) { /* read failure stop now */
        handle_error("Failed to read browser request");
    }
    buffer[ret] = 0; /* terminate the buffer */
    for (i = 0; i < ret; i++) { /* remove CF and LF characters */
        if (buffer[i] == '\r' || buffer[i] == '\n') {
            buffer[i] = '*';
        }
    }
    printf("request %s : %d \n", buffer, hit);
    if (strncmp(buffer, "GET ", 4) && strncmp(buffer, "get ", 4)) {
        printf("Only simple GET operation supported : %s \n", buffer);
        (void)write(fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type, or operation is not allowed on this simple static file web server.\n</body></html>\n", 271);
        exit(EXIT_FAILURE);
    }
    for (i = 4; i < BUFSIZE; i++) { /* null terminate after the second space to ignore extra stuff */
        if (buffer[i] == ' ') { /* string is "GET URL " +lots of other stuff */
            buffer[i] = 0;
            break;
        }
    }
    for (j = 0; j < i - 1; j++) { /* check for illegal parent directory use .. */
        if (buffer[j] == '.' && buffer[j + 1] == '.') {
            printf("directory . or .. is unsupported : %s \n", buffer);
            (void)write(fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type, or operation is not allowed on this simple static file web server.\n</body></html>\n", 271);
            exit(EXIT_FAILURE);
        }
    }
    if (!strncmp(&buffer[0], "GET /\0", 6) || !strncmp(&buffer[0], "get /\0", 6)) {
        (void)strcpy(buffer, "GET /index.html");
    }
    buflen = strlen(buffer);
    fstr = NULL;
    for (i = 0; extensions[i].ext != NULL; i++) {
        len = strlen(extensions[i].ext);
        if (!strncmp(&buffer[buflen - len], extensions[i].ext, len)) {
            fstr = extensions[i].filetype;
            break;
        }
    }
    if (fstr == NULL) {
        printf("Unsupported file type: %s \n", buffer);
        (void)write(fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden -__- </h1>\nThe requested URL, file type, or operation is not allowed on this simple static file web server.\n</body></html>\n", 271);
        exit(EXIT_FAILURE);
    }

    if ((file_fd = open(&buffer[5], O_RDONLY)) == -1) { /* open the file for reading */
        (void)write(fd, "HTTP/1.1 404 Not Found\nContent-Length: 136\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found :(</h1>\nThe requested URL was not found on this server.\n</body></html>\n", 224);
        handle_error("Failed to open file");
    }

    len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */
    if (len == -1) {
        handle_error("Failed to seek file end");
    }
    if (lseek(file_fd, (off_t)0, SEEK_SET) == -1) { /* lseek back to the file start ready for reading */
        handle_error("Failed to seek file start");
    }

    ret = snprintf(buffer, BUFSIZE, "HTTP/1.1 200 OK\nServer: webserver/1.0\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n", len, fstr); /* Header + a blank line */
    if (ret < 0 || ret >= BUFSIZE) {
        handle_error("Failed to construct HTTP response header");
    }

    if (write(fd, buffer, strlen(buffer)) == -1) {
        handle_error("Failed to write HTTP response header");
    }

    /* send file in 8KB block - last block may be smaller */
    while ((ret = read(file_fd, buffer, BUFSIZE)) > 0) {
        if (write(fd, buffer, ret) == -1) {
            handle_error("Failed to write file contents");
        }
    }
    if (ret == -1) {
        handle_error("Failed to read file contents");
    }

    sleep(1); /* allow socket to drain before signaling the socket is closed */
    if (close(fd) == -1) {
        handle_error("Failed to close socket");
    }
    if (close(file_fd) == -1) {
        handle_error("Failed to close file");
    }
    exit(EXIT_SUCCESS);
}

int main() {
    int port, listenfd, socketfd, hit;
    socklen_t length;
    static struct sockaddr_in cli_addr;  /* static = initialized to zeros */
    static struct sockaddr_in serv_addr; /* static = initialized to zeros */

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        handle_error("Failed to initialize socket");
    }

    port = PORT;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); // convert endianness and get the wildcard IP
    serv_addr.sin_port = htons(port);

    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        handle_error("Failed to bind socket");
    }
    if (listen(listenfd, 64) < 0) {
        handle_error("Failed to listen on socket");
    }

    if (chdir(SRV_DIRECTORY) == -1) {
        handle_error("Failed to change directory");
    }

    for (hit = 1;; hit++) {
        length = sizeof(cli_addr);
        if ((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0) {
            handle_error("Failed to accept incoming connection");
        }

        // Fork to handle the incoming connection in a separate process
        pid_t pid = fork();

        if (pid < 0) {
            handle_error("Failed to fork process");
        } else if (pid == 0) {
            // Child process
            if (close(listenfd) == -1) {
                handle_error("Failed to close listening socket in child process");
            }
            web(socketfd, hit); // Handle the request in the child process
        } else {
            // Parent process
            if (close(socketfd) == -1) {
                handle_error("Failed to close socket in parent process");
            }
        }
    }
}
