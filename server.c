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
#define PORT 1234

struct
{
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
    {0, 0}};

void web(int fd, int hit)
{
    int j, file_fd, buflen;
    long i, ret, len;
    char *fstr;
    static char buffer[BUFSIZE + 1]; /* static so zero filled */

    ret = read(fd, buffer, BUFSIZE); /* read Web request in one go */
    if (ret == 0 || ret == -1)
    { /* read failure stop now */
        printf("failed to read browser request \n");
    }
    if (ret > 0 && ret < BUFSIZE) /* return code is valid chars */
        buffer[ret] = 0;          /* terminate the buffer */
    else
        buffer[0] = 0;
    for (i = 0; i < ret; i++) /* remove CF and LF characters */
        if (buffer[i] == '\r' || buffer[i] == '\n')
            buffer[i] = '*';
    printf("request %s : %d \n", buffer, hit);
    if (strncmp(buffer, "GET ", 4) && strncmp(buffer, "get ", 4))
    {
        printf("Only simple GET operation supported : %s \n", buffer);
        (void)write(fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forb1dden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on this simple static file webserver.\n</body></html>\n", 271);
    }
    for (i = 4; i < BUFSIZE; i++)
    { /* null terminate after the second space to ignore extra stuff */
        if (buffer[i] == ' ')
        { /* string is "GET URL " +lots of other stuff */
            buffer[i] = 0;
            break;
        }
    }
    for (j = 0; j < i - 1; j++) /* check for illegal parent directory use .. */
        if (buffer[j] == '.' && buffer[j + 1] == '.')
        {
            printf("directory . or .. is unsupoorted : %s \n", buffer);
            (void)write(fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forb2dden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on this simple static file webserver.\n</body></html>\n", 271);
        }
    if (!strncmp(&buffer[0], "GET /\0", 6) || !strncmp(&buffer[0], "get /\0", 6))
        (void)strcpy(buffer, "GET /index.html");
    buflen = strlen(buffer);
    fstr = (char *)0;
    for (i = 0; extensions[i].ext != 0; i++)
    {
        len = strlen(extensions[i].ext);
        if (!strncmp(&buffer[buflen - len], extensions[i].ext, len))
        {
            fstr = extensions[i].filetype;
            break;
        }
    }
    if (fstr == 0)
    {
        printf("Only simple GET operation supported : %s \n", buffer);
        (void)write(fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forb3dden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on this simple static file webserver.\n</body></html>\n", 271);
    }

    if ((file_fd = open(&buffer[5], O_RDONLY)) == -1)
    { /* open the file for reading */
        printf("failed to open file :");
        (void)write(fd, "HTTP/1.1 404 Not Found\nContent-Length: 136\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\nThe requested URL was not found on this server.\n</body></html>\n", 224);
    }

    len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */
    (void)lseek(file_fd, (off_t)0, SEEK_SET);       /* lseek back to the file start ready for reading */

    (void)sprintf(buffer, "HTTP/1.1 200 OK\nServer: webserver/1.0\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n", len, fstr); /* Header + a blank line */

    (void)write(fd, buffer, strlen(buffer));

    /* send file in 8KB block - last block may be smaller */
    while ((ret = read(file_fd, buffer, BUFSIZE)) > 0)
    {
        (void)write(fd, buffer, ret);
    }
    sleep(1); /* allow socket to drain before signalling the socket is closed */
    close(fd);
    exit(1);
}

int main()
{
    int port, listenfd, socketfd, hit;
    // int i, pid;
    socklen_t length;
    static struct sockaddr_in cli_addr;  /* static = initialised to zeros */
    static struct sockaddr_in serv_addr; /* static = initialised to zeros */

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) // 0 is default protocol as TCP. 
        printf("error init socket");
    port = PORT;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); // convert endieness and get the wildcard ip
    serv_addr.sin_port = htons(port);

    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        printf("error bind socket\n");
    if (listen(listenfd, 64) < 0)
        printf("error listen socket\n");

    if (chdir(SRV_DIRECTORY) == -1)
    {
        (void)printf("ERROR: Can't Change to directory %s\n", SRV_DIRECTORY);
        exit(EXIT_FAILURE);
    }
    for (hit = 1;; hit++)
    {
        length = sizeof(cli_addr);
        if ((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)
            printf("error accept socket\n");

        // Fork to handle the incoming connection in a separate process
        pid_t pid = fork();

        if (pid < 0)
        {
            printf("Error forking process\n");
            exit(EXIT_FAILURE);
        }
        else if (pid == 0)
        {
            // Child process
            close(listenfd);    // Close listening socket in the child process
            web(socketfd, hit); // Handle the request in the child process
            close(socketfd);    // Close the socket in the child process
            exit(EXIT_SUCCESS);
        }
        else
        {
            // Parent process
            close(socketfd); // Close the socket in the parent process
        }
    }
}
