#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <oqs/oqs.h>

#define PORT 1683
#define BUFFER_SIZE 8192

#define SIGNATURE_ALGORITHM OQS_SIG_alg_dilithium_5

typedef struct
{
    char *addr;
    char *cert;
    char *key;
    char *ca_cert;
    char *public_key_path;
    char *private_key_path;
    int peer_fd;
    int server_fd;
    SSL_CTX *ctx;
    SSL *ssl;
    OQS_SIG *sig;
    uint8_t *public_key;
    uint8_t *secret_key;
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

bool peer_read_file(peer_t *p)
{
    int n;
    char buf[BUFFER_SIZE] = {0};
    uint8_t *received_signature = NULL;
    size_t signature_len = 0;

    n = SSL_read(p->ssl, buf, p->sig->length_signature);
    if (n <= 0)
    {
        printf("błąd5\n");
        ERR_print_errors_fp(stderr);
        return false;
    }

    signature_len = n;
    received_signature = malloc(signature_len);
    if (received_signature == NULL)
    {
        printf("błąd6\n");
        return false;
    }
    memcpy(received_signature, buf, signature_len);

    FILE *signature_file = fopen("received_signature.sig", "wb");
    if (signature_file == NULL)
    {
        printf("błąd7\n");
        free(received_signature);
        return false;
    }
    else
    {
        printf("Signature saved\n");
    }

    fwrite(received_signature, 1, signature_len, signature_file);
    fclose(signature_file);

    FILE *file = fopen("received_file", "wb");
    if (file == NULL)
    {
        printf("błąd8\n");
        free(received_signature);
        return false;
    }

    while (true)
    {
        n = SSL_read(p->ssl, buf, BUFFER_SIZE);
        if (n <= 0)
        {
            int ssl_err = SSL_get_error(p->ssl, n);
            if (ssl_err != SSL_ERROR_ZERO_RETURN)
            {
                printf("błąd9\n");
                ERR_print_errors_fp(stderr);
                fclose(file);
                free(received_signature);
                return false;
            }
            printf("File transfer completed\n");
            break;
        }

        fwrite(buf, sizeof(char), n, file);
    }
    fclose(file);

    free(received_signature);

    return true;
}

bool peer_read(peer_t *p)
{
    printf("Select whether you expect to receive a file or a text message\n");
    printf("Type \"file\" to receive a file or \"text\" to receive a text message\n");
    char mode[BUFFER_SIZE], buf[BUFFER_SIZE] = {0};
    scanf("%s", mode);
    if (strcmp(mode, "file") == 0) // strings are identical
    {
        return peer_read_file(p);
    }
    else if (strcmp(mode, "text") != 0) // given text is neither "file" nor "text"
    {
        printf("Invalid inpureadt\n");
        return false;
    }
    printf("waiting for messages from remote peer...\n");
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

bool peer_send_file(peer_t *p)
{
    printf("Enter the path of the file you want to send\n");
    char file_path[BUFFER_SIZE], buf[BUFFER_SIZE] = {0};
    scanf("%s", file_path);

    FILE *file = fopen(file_path, "rb");
    if (file == NULL)
    {
        printf("błąd1");
        return false;
    }

    fseek(file, 0, SEEK_END);
    long file_len = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t *message = malloc(file_len);
    fread(message, 1, file_len, file);
    fclose(file);

    uint8_t *signature = malloc(p->sig->length_signature);
    size_t signature_len;

    if (OQS_SIG_sign(p->sig, signature, &signature_len, message, file_len, p->secret_key) != OQS_SUCCESS)
    {
        printf("błąd5");
        free(message);
        free(signature);
        return false;
    }
    printf("Plik został podpisany\n");

    if (SSL_write(p->ssl, signature, signature_len) <= 0)
    {
        printf("błąd6");
        free(message);
        free(signature);
        return false;
    }

    file = fopen(file_path, "rb");
    size_t n;
    while ((n = fread(buf, 1, BUFFER_SIZE, file)) > 0)
    {
        if (SSL_write(p->ssl, buf, n) <= 0)
        {
            printf("błąd7");
            fclose(file);
            free(message);
            free(signature);
            return false;
        }
    }

    fclose(file);
    printf("File sent successfully\n");

    free(message);
    free(signature);

    return true;
}

bool peer_sig_init(peer_t *p)
{
    OQS_SIG *sig = OQS_SIG_new(SIGNATURE_ALGORITHM);
    if (sig == NULL)
    {
        return false;
    }

    FILE *key_file = fopen(p->private_key_path, "r");

    FILE *public_key_file = fopen(p->public_key_path, "r");
    if (!public_key_file || !key_file)
    {
        perror("Failed to open key file");
        return false;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    EVP_PKEY *public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);

    if (!pkey || !public_key)
    {
        fprintf(stderr, "Error reading private key\n");
        return false;
    }

    uint8_t *priv_key = malloc(sig->length_secret_key);
    uint8_t *pub_key = malloc(sig->length_public_key);

    size_t priv_key_len = sig->length_secret_key;
    size_t pub_key_len = sig->length_public_key;

    if (EVP_PKEY_get_raw_private_key(pkey, priv_key, &priv_key_len) <= 0 ||
        EVP_PKEY_get_raw_public_key(public_key, pub_key, &pub_key_len) <= 0)
    {
        fprintf(stderr, "Failed to extract raw keys\n");
        free(priv_key);
        free(pub_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(public_key);
        return false;
    }

    p->public_key = pub_key;
    p->secret_key = priv_key;
    p->sig = sig;

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(public_key);
    return true;
}

bool peer_write(peer_t *p)
{
    char mode[BUFFER_SIZE];
    printf("Choose whether you want to send a file or a text message\n");
    printf("Type \"file\" to send a file or \"text\" to send a text message\n");
    scanf("%s", mode);
    if (strcmp(mode, "file") == 0)
    {
        return peer_send_file(p);
    }
    else if (strcmp(mode, "text") != 0)
    {
        printf("Invalid inputwrite\n");
        return false;
    }
    printf("reading from stdin...\n");
    printf("type \"quit\" to exit\n");
    char buf[BUFFER_SIZE] = {0};
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
    free(p->public_key);
    free(p->secret_key);
    OQS_SIG_free(p->sig);
    return peer_tls_close(p) && peer_tcp_close(p);
}

bool peer_run(peer_t *p)
{

    if (!peer_sig_init(p))
    {

        return false;
    }
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
    if (argc != 7)
    {
        fprintf(stderr, "usage: %s <addr> <cert> <key> <ca-cert> <public-key> <private-key>\n", argv[0]);
        return EXIT_FAILURE;
    }
    peer_t peer = {
        .addr = argv[1],
        .cert = argv[2],
        .key = argv[3],
        .ca_cert = argv[4],
        .private_key_path = argv[6],
        .public_key_path = argv[5],
        .public_key = NULL,
        .secret_key = NULL,
        .sig = NULL,
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
