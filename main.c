#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#define PORT 1683
#define BUFFER_SIZE 4096

typedef struct
{
    char *addr;
    char *cert;
    char *key;
    char *ca_cert;
    int peer_fd;
    int server_fd;
    SSL_CTX *ctx;
    SSL *ssl;
} peer_t;

bool peer_tcp_accept(peer_t *p)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket");
        return false;
    }
    p->server_fd = server_fd;
    int opt;
    if (setsockopt(
            server_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &opt,
            sizeof(opt)) == -1)
    {
        perror("setsockopt");
        close(server_fd);
        return false;
    }
    struct sockaddr_in server_addr;
    int server_addr_len = sizeof(server_addr);
    memset(&server_addr, 0, server_addr_len);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    if (bind(
            server_fd,
            (struct sockaddr *)&server_addr,
            server_addr_len) == -1)
    {
        perror("bind");
        close(server_fd);
        return false;
    }
    if (listen(server_fd, 1) == -1)
    {
        perror("listen");
        close(server_fd);
        return false;
    }
    printf("listening on 0.0.0.0:%d...\n", PORT);
    struct sockaddr_in peer_addr;
    int peer_addr_len = sizeof(peer_addr);
    int peer_fd = accept(
        server_fd,
        (struct sockaddr *)&peer_addr,
        &peer_addr_len);
    if (peer_fd == -1)
    {
        perror("accept");
        close(server_fd);
        return false;
    }
    p->peer_fd = peer_fd;
    char peer_addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr.sin_addr, peer_addr_str, INET_ADDRSTRLEN);
    printf(
        "connection received from %s:%d\n",
        peer_addr_str,
        ntohs(peer_addr.sin_port));
    return true;
}

bool peer_tcp_connect(peer_t *p)
{
    int peer_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_fd == -1)
    {
        perror("socket");
        return false;
    }
    p->peer_fd = peer_fd;
    struct sockaddr_in peer_addr;
    int peer_addr_len = sizeof(peer_addr);
    memset(&peer_addr, 0, peer_addr_len);
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, p->addr, &peer_addr.sin_addr) == 0)
    {
        fprintf(stderr, "invalid peer address: %s\n", p->addr);
        close(peer_fd);
        return false;
    }
    if (connect(peer_fd, (struct sockaddr *)(&peer_addr), peer_addr_len) == -1)
    {
        printf("could not connect to %s:%d\n", p->addr, PORT);
        close(peer_fd);
        return false;
    }
    printf("connected to %s:%d\n", p->addr, PORT);
    return true;
}

bool peer_tcp_close(peer_t *p)
{
    if ((p->peer_fd != -1 && close(p->peer_fd) == -1) ||
        (p->server_fd != -1 && close(p->server_fd) == -1))
    {
        perror("close");
        return false;
    }
    return true;
}

bool peer_tls_init(peer_t *p, const SSL_METHOD *meth, int mode, int (*handshake_fn)(SSL *ssl))
{
    printf("initializing tls...\n");
    SSL_CTX *ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
    {
        return false;
    }
    p->ctx = ctx;
    if (SSL_CTX_use_certificate_file(ctx, p->cert, SSL_FILETYPE_PEM) != 1)
    {
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, p->key, SSL_FILETYPE_PEM) != 1)
    {
        return false;
    }
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        return false;
    }
    if (SSL_CTX_load_verify_locations(ctx, p->ca_cert, NULL) != 1)
    {
        return false;
    }
    SSL_CTX_set_verify(ctx, mode, NULL);
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        return false;
    }
    p->ssl = ssl;
    if (SSL_set_fd(ssl, p->peer_fd) != 1)
    {
        return false;
    }
    printf("performing tls handshake...\n");
    if (handshake_fn(ssl) != 1)
    {
        return false;
    }
    printf("connection is secure\n");
    return true;
}

bool peer_tls_accept(peer_t *p)
{
    if (!peer_tls_init(
            p,
            TLS_server_method(),
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            SSL_accept))
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool peer_tls_connect(peer_t *p)
{
    if (!peer_tls_init(p, TLS_client_method(), SSL_VERIFY_PEER, SSL_connect))
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool peer_tls_close(peer_t *p)
{
    if (p->ssl != NULL)
    {
        if (SSL_shutdown(p->ssl) != 1)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }
        SSL_free(p->ssl);
    }
    if (p->ctx != NULL)
    {
        SSL_CTX_free(p->ctx);
    }
    return true;
}

bool peer_accept(peer_t *p)
{
    return peer_tcp_accept(p) && peer_tls_accept(p);
}

bool peer_connect(peer_t *p)
{
    return peer_tcp_connect(p) && peer_tls_connect(p);
}

bool peer_read(peer_t *p)
{
    printf("waiting for messages from remote peer...\n");
    char buf[BUFFER_SIZE];
    int n;
    while (true)
    {
        n = SSL_read(p->ssl, buf, BUFFER_SIZE - 1);
        if (n <= 0)
        {
            if (SSL_get_error(p->ssl, n) != SSL_ERROR_ZERO_RETURN)
            {
                ERR_print_errors_fp(stderr);
                return false;
            }
            printf("connection closed by remote peer\n");
            return true;
        }
        buf[n] = '\0';
        printf("%s", buf);
    }
}

bool peer_write(peer_t *p)
{
    printf("reading from stdin...\n");
    printf("type \"quit\" to exit\n");
    char buf[BUFFER_SIZE];
    int buf_len, n;
    while (true)
    {
        if (fgets(buf, BUFFER_SIZE, stdin) == NULL)
        {
            if (!feof(stdin))
            {
                perror("fgets");
                return false;
            }
            return true;
        }
        buf_len = strlen(buf);
        if (buf_len == 5 && strncmp(buf, "quit\n", 5) == 0)
        {
            printf("exiting...\n");
            return true;
        }
        n = SSL_write(p->ssl, buf, buf_len);
        if (n <= 0)
        {
            if (SSL_get_error(p->ssl, n) != SSL_ERROR_ZERO_RETURN)
            {
                ERR_print_errors_fp(stderr);
                return false;
            }
            return true;
        }
    }
}

bool peer_close(peer_t *p)
{
    return peer_tls_close(p) && peer_tcp_close(p);
}

bool peer_run(peer_t *p)
{
    if (peer_connect(p))
    {
        if (peer_read(p))
        {
            if (peer_close(p))
            {
                return true;
            }
            return false;
        }
        peer_close(p);
        return false;
    }
    if (peer_accept(p))
    {
        if (peer_write(p))
        {
            if (peer_close(p))
            {
                return true;
            }
            return false;
        }
        peer_close(p);
        return false;
    }
    return false;
}

int main(int argc, char **argv)
{
    if (argc != 5)
    {
        fprintf(stderr, "usage: %s <addr> <cert> <key> <ca-cert>\n", argv[0]);
        return EXIT_FAILURE;
    }
    peer_t peer = {
        .addr = argv[1],
        .cert = argv[2],
        .key = argv[3],
        .ca_cert = argv[4],
        .peer_fd = -1,
        .server_fd = -1,
        .ctx = NULL,
        .ssl = NULL,
    };
    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (default_prov == NULL)
    {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    OSSL_PROVIDER *oqs_prov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (oqs_prov == NULL)
    {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    if (!peer_run(&peer))
    {
        OSSL_PROVIDER_unload(default_prov);
        OSSL_PROVIDER_unload(oqs_prov);
        return EXIT_FAILURE;
    }
    if (OSSL_PROVIDER_unload(default_prov) == 0)
    {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    if (OSSL_PROVIDER_unload(oqs_prov) == 0)
    {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
