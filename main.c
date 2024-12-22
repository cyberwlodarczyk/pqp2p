#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 1683
#define BUFFER_SIZE 1024

bool start_client(char *addr, int *sock)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1)
    {
        perror("socket");
        return false;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    if (inet_pton(AF_INET, addr, &a.sin_addr) == 0)
    {
        fprintf(stderr, "invalid peer address: %s\n", addr);
        close(s);
        return false;
    }
    if (connect(s, (struct sockaddr *)(&a), sizeof(a)) == -1)
    {
        printf("could not connect to %s:%d\n", addr, PORT);
        close(s);
        return false;
    }
    printf("connected to %s:%d\n", addr, PORT);
    *sock = s;
    return true;
}

bool run_client(int sock)
{
    char b[BUFFER_SIZE];
    int n;
    while (true)
    {
        n = recv(sock, b, BUFFER_SIZE - 1, 0);
        if (n <= 0)
        {
            close(sock);
            if (n == -1)
            {
                perror("recv");
                return false;
            }
            return true;
        }
        b[n] = '\0';
        printf("%s\n", b);
    }
}

bool start_server(int *sock, int *server_sock)
{
    int ss = socket(AF_INET, SOCK_STREAM, 0);
    if (ss == -1)
    {
        perror("socket");
        return false;
    }
    int o;
    if (setsockopt(ss, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o)) == -1)
    {
        perror("setsockopt");
        return false;
    }
    struct sockaddr_in sa;
    socklen_t sal = sizeof(sa);
    memset(&sa, 0, sal);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(PORT);
    if (bind(ss, (struct sockaddr *)&sa, sal) == -1)
    {
        perror("bind");
        close(ss);
        return false;
    }
    if (listen(ss, 1) == -1)
    {
        perror("listen");
        close(ss);
        return false;
    }
    printf("listening on 0.0.0.0:%d...\n", PORT);
    struct sockaddr_in ca;
    socklen_t cal = sizeof(ca);
    int s = accept(ss, (struct sockaddr *)&ca, &cal);
    if (s == -1)
    {
        perror("accept");
        close(ss);
        return false;
    }
    char cip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ca.sin_addr, cip, INET_ADDRSTRLEN);
    printf("connection received from %s:%d\n", cip, ntohs(ca.sin_port));
    *sock = s;
    *server_sock = ss;
    return true;
}

bool run_server(int sock, int server_sock)
{
    char b[BUFFER_SIZE];
    int n;
    while (true)
    {
        if (scanf("%1023s", b) == EOF)
        {
            close(sock);
            close(server_sock);
            if (feof(stdin))
            {
                return true;
            }
            perror("scanf");
            return false;
        }
        n = send(sock, b, strlen(b), 0);
        if (n <= 0)
        {
            close(sock);
            close(server_sock);
            if (n == -1)
            {
                perror("send");
                return false;
            }
            return true;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <ip>\n", argv[0]);
        return EXIT_FAILURE;
    }
    int s;
    if (!start_client(argv[1], &s))
    {
        int ss;
        if (!start_server(&s, &ss))
        {
            return EXIT_FAILURE;
        }
        if (!run_server(s, ss))
        {
            return EXIT_FAILURE;
        }
    }
    else if (!run_client(s))
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
