#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
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
#define BUFFER_SIZE 4096
#define SIGNATURE_ALGORITHM OQS_SIG_alg_dilithium_5
#define SIGNATURE_EXTENSION ".sig"
#define SIGNATURE_EXTENSION_LENGTH (sizeof(SIGNATURE_EXTENSION) - 1)
#define MAX_FILENAME_LENGTH 255
#define QUIT_KEYWORD "quit"
#define QUIT_KEYWORD_LENGTH (sizeof(QUIT_KEYWORD) - 1)

char *add_sig_ext(char *filename)
{
    size_t filename_len = strlen(filename);
    size_t len = filename_len + SIGNATURE_EXTENSION_LENGTH;
    char *result = malloc(len + 1);
    if (result == NULL)
    {
        return NULL;
    }
    memcpy(result, filename, filename_len);
    memcpy(result + filename_len, SIGNATURE_EXTENSION, SIGNATURE_EXTENSION_LENGTH);
    result[len] = '\0';
    return result;
}

typedef struct
{
    char *addr;
    char *cert;
    char *cert_pkey;
    char *ca_cert;
    char *sig_pkey;
    int peer_fd;
    int server_fd;
    OQS_SIG *sig;
    uint8_t *sig_pkey_buf;
    SSL_CTX *ctx;
    SSL *ssl;
} peer_t;

bool peer_sig_init(peer_t *p)
{
    FILE *pkey_file = fopen(p->sig_pkey, "rb");
    if (pkey_file == NULL)
    {
        perror(p->sig_pkey);
        return false;
    }
    EVP_PKEY *pkey_evp = PEM_read_PrivateKey(pkey_file, NULL, NULL, NULL);
    if (pkey_evp == NULL)
    {
        ERR_print_errors_fp(stderr);
        fclose(pkey_file);
        return false;
    }
    if (fclose(pkey_file) != 0)
    {
        perror("fclose");
        EVP_PKEY_free(pkey_evp);
        return false;
    }
    OQS_SIG *sig = OQS_SIG_new(SIGNATURE_ALGORITHM);
    size_t pkey_len = sig->length_secret_key;
    uint8_t *pkey_buf = malloc(pkey_len);
    if (pkey_buf == NULL)
    {
        perror("malloc");
        OQS_SIG_free(sig);
        EVP_PKEY_free(pkey_evp);
        return false;
    }
    if (EVP_PKEY_get_raw_private_key(pkey_evp, pkey_buf, &pkey_len) != 1)
    {
        ERR_print_errors_fp(stderr);
        free(pkey_buf);
        OQS_SIG_free(sig);
        EVP_PKEY_free(pkey_evp);
        return false;
    }
    EVP_PKEY_free(pkey_evp);
    p->sig = sig;
    p->sig_pkey_buf = pkey_buf;
    return true;
}

void peer_sig_free(peer_t *p)
{
    free(p->sig_pkey_buf);
    OQS_SIG_free(p->sig);
}

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
    socklen_t server_addr_len = sizeof(server_addr);
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
    socklen_t peer_addr_len = sizeof(peer_addr);
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
    socklen_t peer_addr_len = sizeof(peer_addr);
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
    if (close(p->peer_fd) != 0 || (p->server_fd != -1 && close(p->server_fd) != 0))
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
    if (SSL_CTX_use_PrivateKey_file(ctx, p->cert_pkey, SSL_FILETYPE_PEM) != 1)
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

int peer_tls_read(peer_t *p, void *buf, int n)
{
    int k = SSL_read(p->ssl, buf, n);
    if (k <= 0)
    {
        int ssl_error = SSL_get_error(p->ssl, k);
        if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == /* ^C was clicked */ SSL_ERROR_SSL)
        {
            return 0;
        }
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 1;
}

int peer_tls_write(peer_t *p, const void *buf, int n)
{
    int k = SSL_write(p->ssl, buf, n);
    if (k <= 0)
    {
        if (SSL_get_error(p->ssl, k) == SSL_ERROR_ZERO_RETURN)
        {
            return 0;
        }
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 1;
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

bool peer_tls_shutdown(peer_t *p)
{
    int n = SSL_shutdown(p->ssl);
    if (n == 1)
    {
        return true;
    }
    if (n == 0)
    {
        n = SSL_shutdown(p->ssl);
    }
    if (n == 1)
    {
        return true;
    }
    return false;
}

bool peer_tls_close(peer_t *p)
{
    bool ok = peer_tls_shutdown(p);
    SSL_free(p->ssl);
    SSL_CTX_free(p->ctx);
    return ok;
}

bool peer_accept(peer_t *p)
{
    return peer_tcp_accept(p) && peer_tls_accept(p);
}

bool peer_connect(peer_t *p)
{
    return peer_tcp_connect(p) && peer_tls_connect(p);
}

char *peer_read_filename(peer_t *p)
{
    uint8_t *filename_len = malloc(1);
    if (filename_len == NULL)
    {
        perror("malloc");
        return NULL;
    }
    if (peer_tls_read(p, filename_len, 1) != 1)
    {
        free(filename_len);
        return NULL;
    }
    char *filename = malloc(*filename_len + 1);
    if (filename == NULL)
    {
        perror("malloc");
        free(filename_len);
        return NULL;
    }
    if (*filename_len == 0)
    {
        filename[0] = '\0';
        free(filename_len);
        return filename;
    }
    if (peer_tls_read(p, filename, *filename_len) != 1)
    {
        free(filename);
        free(filename_len);
        return NULL;
    }
    filename[*filename_len] = '\0';
    free(filename_len);
    return filename;
}

size_t peer_read_file_len(peer_t *p)
{
    const int n = sizeof(size_t);
    uint8_t buf[n];
    if (peer_tls_read(p, buf, n) != 1)
    {
        return -1;
    }
    size_t len;
    memcpy(&len, buf, n);
    return len;
}

bool peer_read_file(peer_t *p, char *filename)
{
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        perror(filename);
        return false;
    }
    size_t file_len = peer_read_file_len(p);
    if (file_len == -1)
    {
        fclose(file);
        return false;
    }
    int n;
    uint8_t buf[BUFFER_SIZE];
    while (true)
    {
        n = file_len < BUFFER_SIZE ? file_len : BUFFER_SIZE;
        if (peer_tls_read(p, buf, n) != 1)
        {
            fclose(file);
            return false;
        }
        if (fwrite(buf, 1, n, file) != n)
        {
            perror("fwrite");
            fclose(file);
            return false;
        }
        if (file_len <= BUFFER_SIZE)
        {
            if (fclose(file) != 0)
            {
                perror("fclose");
                return false;
            }
            return true;
        }
        file_len -= BUFFER_SIZE;
    }
}

bool peer_read_sig(peer_t *p, char *filename)
{
    size_t sig_len = p->sig->length_signature;
    uint8_t *sig = malloc(sig_len);
    if (sig == NULL)
    {
        perror("malloc");
        return false;
    }
    if (peer_tls_read(p, sig, sig_len) != 1)
    {
        free(sig);
        return false;
    }
    char *sig_filename = add_sig_ext(filename);
    if (sig_filename == NULL)
    {
        free(sig);
        return false;
    }
    FILE *sig_file = fopen(sig_filename, "wb");
    if (sig_file == NULL)
    {
        free(sig_filename);
        free(sig);
        return false;
    }
    free(sig_filename);
    if (fwrite(sig, 1, sig_len, sig_file) != sig_len)
    {
        perror("fwrite");
        fclose(sig_file);
        free(sig);
        return false;
    }
    free(sig);
    if (fclose(sig_file) != 0)
    {
        perror("fclose");
        return false;
    }
    return true;
}

bool peer_read(peer_t *p)
{
    printf("waiting for files...\n");
    while (true)
    {
        char *filename = peer_read_filename(p);
        if (filename == NULL)
        {
            return false;
        }
        if (filename[0] == '\0')
        {
            free(filename);
            printf("done\n");
            return true;
        }
        if (!peer_read_file(p, filename) || !peer_read_sig(p, filename))
        {
            free(filename);
            return false;
        }
        printf("< %s\n", filename);
        free(filename);
    }
}

char *peer_write_filename(peer_t *p)
{
    char *filename = malloc(MAX_FILENAME_LENGTH + 1);
    if (filename == NULL)
    {
        return NULL;
    }
    printf("> ");
    fflush(stdout);
    if (fgets(filename, MAX_FILENAME_LENGTH + 1, stdin) == NULL)
    {
        perror("fgets");
        free(filename);
        return NULL;
    }
    filename[strcspn(filename, "\n")] = '\0';
    if(access(filename, F_OK) != 0) 
    {
        fprintf(stderr, "No file with name %s\n", filename);
        return NULL;
    }
    char * filename_copy = strdup(filename);
    char *base_filename = basename(filename_copy);
    uint8_t base_filename_len = strlen(base_filename);
    if (filename[0] == '\0' || strcmp(filename, QUIT_KEYWORD) == 0)
    {
        filename[0] = '\0';
        base_filename_len = 0;
    }
    if (peer_tls_write(p, &base_filename_len, 1) != 1 || (base_filename_len != 0 && peer_tls_write(p, base_filename, base_filename_len) != 1))
    {
        free(filename);
        free(filename_copy);
        return NULL;
    }
    free(filename_copy);
    return filename;
}

size_t peer_write_file_len(peer_t *p, FILE *file)
{
    const int n = sizeof(size_t);
    if (fseek(file, 0, SEEK_END) != 0)
    {
        perror("fseek");
        return -1;
    }
    size_t len = ftell(file);
    if (len == -1)
    {
        perror("ftell");
        return -1;
    }
    if (fseek(file, 0, SEEK_SET) != 0)
    {
        perror("fseek");
        return -1;
    }
    uint8_t buf[n];
    memcpy(buf, &len, n);
    if (peer_tls_write(p, buf, n) != 1)
    {
        return -1;
    }
    return len;
}

uint8_t *peer_write_file(peer_t *p, FILE *file, size_t file_len)
{
    uint8_t *content = malloc(file_len);
    if (content == NULL)
    {
        return NULL;
    }
    if (fread(content, 1, file_len, file) != file_len)
    {
        perror("fread");
        free(content);
        return NULL;
    }
    if (peer_tls_write(p, content, file_len) != 1)
    {
        free(content);
        return NULL;
    }
    return content;
}

bool peer_write_sig(peer_t *p, uint8_t *file_content, size_t file_len)
{
    size_t sig_len = p->sig->length_signature;
    uint8_t *sig = malloc(sig_len);
    if (sig == NULL)
    {
        return false;
    }
    if (OQS_SIG_sign(p->sig, sig, &sig_len, file_content, file_len, p->sig_pkey_buf) != OQS_SUCCESS)
    {
        free(sig);
        return false;
    }
    if (peer_tls_write(p, sig, sig_len) != 1)
    {
        free(sig);
        return false;
    }
    free(sig);
    return true;
}

bool peer_write(peer_t *p)
{
    printf("enter name of the file to be send\n");
    printf("type \"%s\" or an empty string to exit\n", QUIT_KEYWORD);
    while (true)
    {
        char *filename = peer_write_filename(p);
        if (filename == NULL)
        {
            return false;
        }
        if (filename[0] == '\0')
        {
            free(filename);
            return true;
        }
        FILE *file = fopen(filename, "rb");
        if (file == NULL)
        {
            perror(filename);
            free(filename);
            return false;
        }
        free(filename);
        size_t file_len = peer_write_file_len(p, file);
        if (file_len == -1)
        {
            fclose(file);
            return false;
        }
        uint8_t *file_content = peer_write_file(p, file, file_len);
        if (file_content == NULL)
        {
            fclose(file);
            return false;
        }
        if (!peer_write_sig(p, file_content, file_len))
        {
            fclose(file);
            free(file_content);
            return false;
        }
        free(file_content);
        if (fclose(file) != 0)
        {
            perror("fclose");
            return false;
        }
    }
}

bool peer_close(peer_t *p)
{
    if (!peer_tls_close(p) || !peer_tcp_close(p))
    {
        return false;
    }
    peer_sig_free(p);
    return true;
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

int run(int argc, char **argv)
{
    if (argc != 6)
    {
        fprintf(stderr, "usage: %s <addr> <cert> <cert-pkey> <ca-cert> <sig-pkey>\n", argv[0]);
        return EXIT_FAILURE;
    }
    peer_t peer = {
        .addr = argv[1],
        .cert = argv[2],
        .cert_pkey = argv[3],
        .ca_cert = argv[4],
        .sig_pkey = argv[5],
        .peer_fd = -1,
        .server_fd = -1,
        .sig = NULL,
        .sig_pkey_buf = NULL,
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

int main(int argc, char **argv)
{
    int code = run(argc, argv);
    printf("exit status %d\n", code);
    return code;
}
