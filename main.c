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

bool peer_tcp_accept(peer_t *peer)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket");
        return false;
    }
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
    char peer_addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr.sin_addr, peer_addr_str, INET_ADDRSTRLEN);
    printf(
        "connection received from %s:%d\n",
        peer_addr_str,
        ntohs(peer_addr.sin_port));
    peer->peer_fd = peer_fd;
    peer->server_fd = server_fd;
    return true;
}

bool peer_tcp_connect(peer_t *peer)
{
    int peer_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_fd == -1)
    {
        perror("socket");
        return false;
    }
    struct sockaddr_in peer_addr;
    int peer_addr_len = sizeof(peer_addr);
    memset(&peer_addr, 0, peer_addr_len);
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, peer->addr, &peer_addr.sin_addr) == 0)
    {
        fprintf(stderr, "invalid peer address: %s\n", peer->addr);
        close(peer_fd);
        return false;
    }
    if (connect(peer_fd, (struct sockaddr *)(&peer_addr), peer_addr_len) == -1)
    {
        printf("could not connect to %s:%d\n", peer->addr, PORT);
        close(peer_fd);
        return false;
    }
    printf("connected to %s:%d\n", peer->addr, PORT);
    peer->peer_fd = peer_fd;
    return true;
}

bool peer_tcp_close(peer_t *peer)
{
    if ((peer->peer_fd != -1 && close(peer->peer_fd) == -1) ||
        (peer->server_fd != -1 && close(peer->server_fd) == -1))
    {
        perror("close");
        return false;
    }
    return true;
}

bool peer_tls_init(peer_t *peer, const SSL_METHOD *meth, int mode)
{
    SSL_CTX *ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
    {
        return false;
    }
    if (SSL_CTX_use_certificate_file(ctx, peer->cert, SSL_FILETYPE_PEM) != 1)
    {
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, peer->key, SSL_FILETYPE_PEM) != 1)
    {
        return false;
    }
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        return false;
    }
    if (SSL_CTX_load_verify_locations(ctx, peer->ca_cert, NULL) != 1)
    {
        return false;
    }
    SSL_CTX_set_verify(ctx, mode, NULL);
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        return false;
    }
    if (SSL_set_fd(ssl, peer->peer_fd) != 1)
    {
        return false;
    }
    peer->ctx = ctx;
    peer->ssl = ssl;
    return true;
}

bool peer_tls_accept(peer_t *peer)
{
    if (!peer_tls_init(
            peer,
            TLS_server_method(),
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) ||
        SSL_accept(peer->ssl) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool peer_tls_connect(peer_t *peer)
{
    if (!peer_tls_init(peer, TLS_client_method(), SSL_VERIFY_PEER) ||
        SSL_connect(peer->ssl) != 1)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool peer_tls_close(peer_t *peer)
{
    if (peer->ssl != NULL)
    {
        if (SSL_shutdown(peer->ssl) != 1)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }
        SSL_free(peer->ssl);
    }
    if (peer->ctx != NULL)
    {
        SSL_CTX_free(peer->ctx);
    }
    return true;
}

bool peer_accept(peer_t *peer)
{
    return peer_tcp_accept(peer) && peer_tls_accept(peer);
}

bool peer_connect(peer_t *peer)
{
    return peer_tcp_connect(peer) && peer_tls_connect(peer);
}

bool peer_read(peer_t *peer)
{
    char buf[BUFFER_SIZE];
    int n;
    while (true)
    {
        n = SSL_read(peer->ssl, buf, BUFFER_SIZE - 1);
        if (n <= 0)
        {
            if (SSL_get_error(peer->ssl, n) != SSL_ERROR_ZERO_RETURN)
            {
                ERR_print_errors_fp(stderr);
                return false;
            }
            return true;
        }
        buf[n] = '\0';
        printf("%s", buf);
    }
}

bool peer_write(peer_t *peer)
{
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
        if (buf_len == 5 && strncmp(buf, "exit\n", 5) == 0)
        {
            return true;
        }
        n = SSL_write(peer->ssl, buf, buf_len);
        if (n <= 0)
        {
            if (SSL_get_error(peer->ssl, n) != SSL_ERROR_ZERO_RETURN)
            {
                ERR_print_errors_fp(stderr);
                return false;
            }
            return true;
        }
    }
}

bool peer_close(peer_t *peer)
{
    return peer_tls_close(peer) && peer_tcp_close(peer);
}

bool peer_run(peer_t *peer)
{
    if (peer_connect(peer))
    {
        if (peer_read(peer))
        {
            if (peer_close(peer))
            {
                return true;
            }
            return false;
        }
        peer_close(peer);
        return false;
    }
    if (peer_accept(peer))
    {
        if (peer_write(peer))
        {
            if (peer_close(peer))
            {
                return true;
            }
            return false;
        }
        peer_close(peer);
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
