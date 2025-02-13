#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
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
#define CMD_PREFIX_CHAR '\\'

bool debug = false;

void print_symbol(char symbol, int color)
{
    printf("\033[%dm", color);
    putchar(symbol);
    printf("\033[0m");
    putchar(' ');
}

void vflogf(FILE *file, const char *label, int color, const char *format, va_list args)
{
    fprintf(file, "\033[%dm", color);
    fprintf(file, "[%s]", label);
    fprintf(file, "\033[0m");
    putc(' ', file);
    vfprintf(file, format, args);
    putc('\n', file);
}

void debugf(const char *format, ...)
{
    if (!debug)
    {
        return;
    }
    va_list args;
    va_start(args, format);
    vflogf(stdout, "debug", 90, format, args);
    va_end(args);
}

void fatalf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vflogf(stderr, "fatal", 35, format, args);
    va_end(args);
}

void vmsgf(char symbol, int color, const char *format, va_list args)
{
    print_symbol(symbol, color);
    vprintf(format, args);
    putchar('\n');
}

void commentf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vmsgf('#', 90, format, args);
    va_end(args);
}

void errorf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vmsgf('!', 91, format, args);
    va_end(args);
}

void prompt()
{
    print_symbol('>', 94);
    fflush(stdout);
}

char *add_sig_ext(char *filename)
{
    size_t filename_len = strlen(filename);
    size_t len = filename_len + SIGNATURE_EXTENSION_LENGTH;
    char *result = OPENSSL_malloc(len + 1);
    if (result == NULL)
    {
        return NULL;
    }
    memcpy(result, filename, filename_len);
    memcpy(result + filename_len, SIGNATURE_EXTENSION, SIGNATURE_EXTENSION_LENGTH);
    result[len] = '\0';
    return result;
}

uint64_t get_file_size(FILE *file)
{
    if (fseek(file, 0, SEEK_END) != 0)
    {
        perror("fseek");
        return -1;
    }
    uint64_t len = ftell(file);
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
    return len;
}

bool str_to_uint8(char *str, uint8_t *n)
{
    size_t len = strlen(str);
    if (len > 3)
    {
        return false;
    }
    if (len == 3 && (str[0] != '1' && str[0] != '2'))
    {
        return false;
    }
    uint8_t t = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (str[i] < '0' || str[i] > '9')
        {
            return false;
        }
        if (i == 0 && str[i] == '0')
        {
            return false;
        }
        t *= 10;
        t += str[i] - '0';
    }
    *n = t;
    return true;
}

typedef enum
{
    CMD_TYPE_UPLOAD,
    CMD_TYPE_DOWNLOAD,
    CMD_TYPE_HELP,
    CMD_TYPE_QUIT,
} cmd_type_t;

#define CMD_TYPE_UPLOAD_STR "upload"
#define CMD_TYPE_DOWNLOAD_STR "download"
#define CMD_TYPE_HELP_STR "help"
#define CMD_TYPE_QUIT_STR "quit"

cmd_type_t cmd_type_from_str(char *str)
{
    if (strcmp(str, CMD_TYPE_UPLOAD_STR) == 0)
    {
        return CMD_TYPE_UPLOAD;
    }
    if (strcmp(str, CMD_TYPE_DOWNLOAD_STR) == 0)
    {
        return CMD_TYPE_DOWNLOAD;
    }
    if (strcmp(str, CMD_TYPE_HELP_STR) == 0)
    {
        return CMD_TYPE_HELP;
    }
    if (strcmp(str, CMD_TYPE_QUIT_STR) == 0)
    {
        return CMD_TYPE_QUIT;
    }
    return -1;
}

typedef struct
{
    cmd_type_t type;
    int args_len;
    char **args;
} cmd_t;

cmd_t *cmd_parse(char *buf)
{
    cmd_t *c = OPENSSL_malloc(sizeof(cmd_t));
    if (c == NULL)
    {
        perror("malloc");
        return NULL;
    }
    char *type = strtok(buf, " ");
    c->type = cmd_type_from_str(type);
    if (c->type == -1)
    {
        OPENSSL_free(c);
        fatalf("invalid command: %s", buf);
        return NULL;
    }
    size_t capacity = 4;
    c->args_len = 0;
    c->args = OPENSSL_malloc(capacity * sizeof(char *));
    if (c->args == NULL)
    {
        perror("malloc");
        OPENSSL_free(c);
        return NULL;
    }
    while (true)
    {
        char *arg = strtok(NULL, " ");
        if (arg == NULL)
        {
            break;
        }
        c->args[c->args_len++] = arg;
        if (c->args_len == capacity)
        {
            capacity *= 2;
            char **args = OPENSSL_realloc(c->args, capacity * sizeof(char *));
            if (args == NULL)
            {
                perror("realloc");
                OPENSSL_free(c->args);
                OPENSSL_free(c);
                return NULL;
            }
            c->args = args;
        }
    }
    return c;
}

void cmd_free(cmd_t *c)
{
    OPENSSL_free(c->args);
    OPENSSL_free(c);
}

typedef enum
{
    MESSAGE_TEXT,
    MESSAGE_UPLOAD,
    MESSAGE_DOWNLOAD,
    MESSAGE_QUIT,
} message_t;

#define FILE_STORE_SIZE 16

typedef struct
{
    uint8_t id;
    char *pathname;
} file_store_item_t;

typedef struct
{
    file_store_item_t items[FILE_STORE_SIZE];
    size_t size;
} file_store_t;

file_store_t *file_store_new()
{
    file_store_t *fs = OPENSSL_malloc(sizeof(file_store_t));
    if (fs == NULL)
    {
        return NULL;
    }
    fs->size = 0;
    return fs;
}

bool file_store_add(file_store_t *fs, uint8_t id, char *pathname)
{
    if (fs->size == FILE_STORE_SIZE)
    {
        return false;
    }
    file_store_item_t item = {.id = id, .pathname = pathname};
    fs->items[fs->size++] = item;
    return true;
}

char *file_store_get(file_store_t *fs, uint8_t id)
{
    for (size_t i = 0; i < fs->size; i++)
    {
        if (fs->items[i].id == id)
        {
            return fs->items[i].pathname;
        }
    }
    return NULL;
}

bool file_store_remove(file_store_t *fs, uint8_t id)
{
    for (size_t i = 0; i < fs->size; i++)
    {
        if (fs->items[i].id != id)
        {
            continue;
        }
        if (i != fs->size - 1)
        {
            memcpy(&fs->items[i], &fs->items[fs->size - 1], sizeof(file_store_item_t));
        }
        fs->size--;
        return true;
    }
    return false;
}

void file_store_free(file_store_t *s)
{
    OPENSSL_free(s);
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
    uint8_t upload_next_id;
    file_store_t *upload_store;
    file_store_t *download_store;
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
    uint8_t *pkey_buf = OPENSSL_malloc(pkey_len);
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
        OPENSSL_clear_free(pkey_buf, pkey_len);
        OQS_SIG_free(sig);
        EVP_PKEY_free(pkey_evp);
        return false;
    }
    EVP_PKEY_free(pkey_evp);
    p->sig = sig;
    p->sig_pkey_buf = pkey_buf;
    return true;
}

uint8_t *peer_sig_sign(peer_t *p, uint8_t *msg, size_t msg_len)
{
    size_t sig_len = p->sig->length_signature;
    uint8_t *sig = OPENSSL_malloc(sig_len);
    if (sig == NULL)
    {
        perror("malloc");
        return NULL;
    }
    if (OQS_SIG_sign(p->sig, sig, &sig_len, msg, msg_len, p->sig_pkey_buf) != OQS_SUCCESS)
    {
        OPENSSL_free(sig);
        return NULL;
    }
    return sig;
}

void peer_sig_free(peer_t *p)
{
    OPENSSL_clear_free(p->sig_pkey_buf, p->sig->length_secret_key);
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
    debugf("listening on 0.0.0.0:%d...", PORT);
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
    debugf("connection received from %s:%d",
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
        fatalf("invalid peer address: %s", p->addr);
        close(peer_fd);
        return false;
    }
    if (connect(peer_fd, (struct sockaddr *)(&peer_addr), peer_addr_len) == -1)
    {
        debugf("could not connect to %s:%d", p->addr, PORT);
        close(peer_fd);
        return false;
    }
    debugf("connected to %s:%d", p->addr, PORT);
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
    debugf("initializing tls...");
    SSL_CTX *ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
    {
        return false;
    }
    p->ctx = ctx;
    if (SSL_CTX_set1_groups_list(ctx, "kyber1024") != 1)
    {
        return false;
    }
    if (SSL_CTX_set1_sigalgs_list(ctx, "dilithium5") != 1)
    {
        return false;
    }
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
    debugf("performing tls handshake...");
    if (handshake_fn(ssl) != 1)
    {
        return false;
    }
    debugf("connection is secure");
    return true;
}

bool peer_tls_read(peer_t *p, void *buf, int n)
{
    if (SSL_read(p->ssl, buf, n) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool peer_tls_write(peer_t *p, const void *buf, int n)
{
    if (SSL_write(p->ssl, buf, n) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
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

bool peer_read_uint8(peer_t *p, uint8_t *n)
{
    return peer_tls_read(p, n, 1);
}

bool peer_read_uint16(peer_t *p, uint16_t *n)
{
    return peer_tls_read(p, n, 2);
}

bool peer_read_uint64(peer_t *p, uint64_t *n)
{
    return peer_tls_read(p, n, 8);
}

bool peer_read_file_content(peer_t *p, char *filename, uint64_t size)
{
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        perror(filename);
        return false;
    }
    uint64_t n;
    uint8_t buf[BUFFER_SIZE];
    while (true)
    {
        n = size < BUFFER_SIZE ? size : BUFFER_SIZE;
        if (!peer_tls_read(p, buf, n))
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
        if (size <= BUFFER_SIZE)
        {
            if (fclose(file) != 0)
            {
                perror("fclose");
                return false;
            }
            return true;
        }
        size -= BUFFER_SIZE;
    }
}

bool peer_read_file_sig(peer_t *p, char *filename)
{
    size_t len = p->sig->length_signature;
    uint8_t *sig = OPENSSL_malloc(len);
    if (sig == NULL)
    {
        perror("malloc");
        return false;
    }
    if (!peer_tls_read(p, sig, len))
    {
        OPENSSL_free(sig);
        return false;
    }
    filename = add_sig_ext(filename);
    if (filename == NULL)
    {
        OPENSSL_free(sig);
        return false;
    }
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        OPENSSL_free(filename);
        OPENSSL_free(sig);
        return false;
    }
    OPENSSL_free(filename);
    if (fwrite(sig, 1, len, file) != len)
    {
        perror("fwrite");
        fclose(file);
        OPENSSL_free(sig);
        return false;
    }
    OPENSSL_free(sig);
    if (fclose(file) != 0)
    {
        perror("fclose");
        return false;
    }
    return true;
}

bool peer_read_file(peer_t *p, char *filename)
{
    uint64_t size;
    return peer_read_uint64(p, &size) &&
           peer_read_file_content(p, filename, size) &&
           peer_read_file_sig(p, filename);
}

bool peer_write_uint8(peer_t *p, uint8_t n)
{
    return peer_tls_write(p, &n, 1);
}

bool peer_write_uint16(peer_t *p, uint16_t n)
{
    return peer_tls_write(p, &n, 2);
}

bool peer_write_uint64(peer_t *p, uint64_t n)
{
    return peer_tls_write(p, &n, 8);
}

bool peer_rx_text(peer_t *p)
{
    uint16_t len;
    if (!peer_read_uint16(p, &len))
    {
        return false;
    }
    char *text = OPENSSL_malloc(len + 1);
    if (text == NULL)
    {
        perror("malloc");
        return false;
    }
    if (!peer_tls_read(p, text, len))
    {
        OPENSSL_free(text);
        return false;
    }
    text[len] = '\0';
    print_symbol('<', 92);
    printf("%s\n", text);
    OPENSSL_free(text);
    return true;
}

bool peer_rx_upload_filename(peer_t *p)
{
    uint8_t id, len;
    if (!peer_read_uint8(p, &id) || !peer_read_uint8(p, &len))
    {
        return false;
    }
    char *filename = OPENSSL_malloc(len + 1);
    if (filename == NULL)
    {
        perror("malloc");
        return false;
    }
    if (!peer_tls_read(p, filename, len))
    {
        OPENSSL_free(filename);
        return false;
    }
    filename[len] = '\0';
    file_store_add(p->download_store, id, filename);
    commentf("%s (%d)", filename, id);
    return true;
}

bool peer_rx_upload(peer_t *p)
{
    uint8_t count;
    if (!peer_read_uint8(p, &count))
    {
        return false;
    }
    if (count == 0)
    {
        return true;
    }
    if (count == 1)
    {
        commentf("1 new file is available for download");
    }
    else
    {
        commentf("%d new files are available for download", count);
    }
    for (uint8_t i = 0; i < count; i++)
    {
        if (!peer_rx_upload_filename(p))
        {
            return false;
        }
    }
    return true;
}

bool peer_rx_download_file(peer_t *p)
{
    uint8_t id;
    if (!peer_read_uint8(p, &id))
    {
        return false;
    }
    char *pathname = file_store_get(p->upload_store, id);
    if (pathname == NULL)
    {
        return false;
    }
    commentf("%s (%d)", pathname, id);
    FILE *file = fopen(pathname, "rb");
    if (file == NULL)
    {
        perror(pathname);
        return false;
    }
    uint64_t size = get_file_size(file);
    if (size == -1)
    {
        fclose(file);
        return false;
    }
    if (!peer_write_uint64(p, size))
    {
        fclose(file);
        return false;
    }
    uint8_t *content = OPENSSL_malloc(size);
    if (content == NULL)
    {
        perror("malloc");
        fclose(file);
        return false;
    }
    if (fread(content, 1, size, file) != size)
    {
        perror("fread");
        fclose(file);
        OPENSSL_free(content);
        return false;
    }
    if (fclose(file) != 0)
    {
        perror("fclose");
        OPENSSL_free(content);
        return false;
    }
    if (!peer_tls_write(p, content, size))
    {
        OPENSSL_free(content);
        return false;
    }
    uint8_t *sig = peer_sig_sign(p, content, size);
    if (sig == NULL)
    {
        OPENSSL_free(content);
        return false;
    }
    OPENSSL_free(content);
    if (!peer_tls_write(p, sig, p->sig->length_signature))
    {
        OPENSSL_free(sig);
        return false;
    }
    OPENSSL_free(sig);
    file_store_remove(p->upload_store, id);
    return true;
}

bool peer_rx_download(peer_t *p)
{
    uint8_t count;
    if (!peer_read_uint8(p, &count))
    {
        return false;
    }
    if (count == 0)
    {
        return true;
    }
    if (count == 1)
    {
        commentf("sending 1 file");
    }
    else
    {
        commentf("sending %d files", count);
    }
    for (uint8_t i = 0; i < count; i++)
    {
        if (!peer_rx_download_file(p))
        {
            return false;
        }
    }
    return true;
}

bool peer_rx(peer_t *p)
{
    while (true)
    {
        uint8_t mode;
        if (!peer_read_uint8(p, &mode))
        {
            return false;
        }
        if (mode == MESSAGE_TEXT)
        {
            if (!peer_rx_text(p))
            {
                return false;
            }
        }
        else if (mode == MESSAGE_UPLOAD)
        {
            if (!peer_rx_upload(p))
            {
                return false;
            }
        }
        else if (mode == MESSAGE_DOWNLOAD)
        {
            if (!peer_rx_download(p))
            {
                return false;
            }
        }
        else if (mode == MESSAGE_QUIT)
        {
            return true;
        }
    }
}

bool peer_tx_text(peer_t *p, char *text)
{
    if (!peer_write_uint8(p, MESSAGE_TEXT))
    {
        return false;
    }
    uint16_t len = strlen(text);
    return peer_write_uint16(p, len) && peer_tls_write(p, text, len);
}

bool peer_tx_upload_filename(peer_t *p, char *pathname)
{
    uint8_t id = p->upload_next_id++;
    file_store_add(p->upload_store, id, pathname);
    char *filename = basename(pathname);
    uint8_t len = strlen(filename);
    return peer_write_uint8(p, id) && peer_write_uint8(p, len) && peer_tls_write(p, filename, len);
}

bool peer_tx_upload(peer_t *p, char **pathnames, uint8_t count)
{
    if (count == 0)
    {
        errorf("no file paths specified");
        return true;
    }
    if (!peer_write_uint8(p, MESSAGE_UPLOAD) || !peer_write_uint8(p, count))
    {
        return false;
    }
    for (uint8_t i = 0; i < count; i++)
    {
        if (!peer_tx_upload_filename(p, pathnames[i]))
        {
            return false;
        }
    }
    if (count == 1)
    {
        commentf("1 file offered for download");
    }
    else
    {
        commentf("%d file(s) offered for download", count);
    }
    return true;
}

bool peer_tx_download_file(peer_t *p, uint8_t id, char *filename)
{
    commentf("%s (%d)", filename, id);
    if (!peer_write_uint8(p, id) || !peer_read_file(p, filename))
    {
        return false;
    }
    file_store_remove(p->download_store, id);
    // OPENSSL_free(filename);
    return true;
}

bool peer_tx_download(peer_t *p, char **str_ids, uint8_t count)
{
    if (count == 0)
    {
        errorf("no file ids specified");
        return true;
    }
    file_store_item_t *items = OPENSSL_malloc(count * sizeof(file_store_item_t));
    if (items == NULL)
    {
        return false;
    }
    for (uint8_t i = 0; i < count; i++)
    {
        file_store_item_t *item = &items[i];
        if (!str_to_uint8(str_ids[i], &item->id))
        {
            OPENSSL_free(items);
            errorf("invalid file id \"%s\"", str_ids[i]);
            return true;
        }
        item->pathname = file_store_get(p->download_store, item->id);
        if (item->pathname == NULL)
        {
            OPENSSL_free(items);
            errorf("file with id %d not found", item->id);
            return true;
        }
    }
    if (!peer_write_uint8(p, MESSAGE_DOWNLOAD) || !peer_write_uint8(p, count))
    {
        OPENSSL_free(items);
        return false;
    }
    for (uint8_t i = 0; i < count; i++)
    {
        if (!peer_tx_download_file(p, items[i].id, items[i].pathname))
        {
            OPENSSL_free(items);
            return false;
        }
    }
    OPENSSL_free(items);
    if (count == 1)
    {
        commentf("successfully downloaded 1 file");
    }
    else
    {
        commentf("successfully downloaded %d files", count);
    }
    return true;
}

bool peer_tx(peer_t *p)
{
    char buf[BUFFER_SIZE];
    while (true)
    {
        prompt();
        if (fgets(buf, BUFFER_SIZE, stdin) == NULL)
        {
            perror("fgets");
            return false;
        }
        buf[strcspn(buf, "\n")] = '\0';
        if (buf[0] == CMD_PREFIX_CHAR)
        {
            cmd_t *cmd = cmd_parse(buf + 1);
            if (cmd == NULL)
            {
                continue;
            }
            switch (cmd->type)
            {
            case CMD_TYPE_UPLOAD:
                if (!peer_tx_upload(p, cmd->args, cmd->args_len))
                {
                    cmd_free(cmd);
                    return false;
                }
                break;
            case CMD_TYPE_DOWNLOAD:
                if (!peer_tx_download(p, cmd->args, cmd->args_len))
                {
                    cmd_free(cmd);
                    return false;
                }
                break;
            case CMD_TYPE_HELP:
                printf("TODO\n");
                break;
            case CMD_TYPE_QUIT:
                cmd_free(cmd);
                return peer_write_uint8(p, MESSAGE_QUIT);
            }
            cmd_free(cmd);
        }
        else if (!peer_tx_text(p, buf))
        {
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
    file_store_free(p->upload_store);
    file_store_free(p->download_store);
    return true;
}

bool peer_run(peer_t *p)
{
    p->upload_store = file_store_new();
    p->download_store = file_store_new();
    if (!peer_sig_init(p))
    {
        return false;
    }
    if (peer_connect(p))
    {
        file_store_add(p->upload_store, 1, "a.txt");
        file_store_add(p->upload_store, 2, "b.txt");
        file_store_add(p->upload_store, 3, "c.txt");
        if (peer_rx(p))
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
        file_store_add(p->download_store, 1, "a.txt");
        file_store_add(p->download_store, 2, "b.txt");
        file_store_add(p->download_store, 3, "c.txt");
        if (peer_tx(p))
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

int run_peer(int argc, char **argv)
{
    if (argc != 6)
    {
        fatalf("usage: %s <addr> <cert> <cert-pkey> <ca-cert> <sig-pkey>", argv[0]);
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
        .upload_next_id = 0,
        .upload_store = NULL,
        .download_store = NULL,
        .sig = NULL,
        .sig_pkey_buf = NULL,
        .ctx = NULL,
        .ssl = NULL,
    };
    return peer_run(&peer) ? EXIT_SUCCESS : EXIT_FAILURE;
}

int run_with_oqs_provider(int argc, char **argv)
{
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
    int code = run_peer(argc, argv);
    if (code == EXIT_FAILURE)
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

int run_with_oqs(int argc, char **argv)
{
    debugf("using oqs version %s", OQS_version());
    OQS_init();
    int code = run_with_oqs_provider(argc, argv);
    OQS_destroy();
    return code;
}

int run(int argc, char **argv)
{
    char *debug_env = getenv("DEBUG");
    debug = debug_env != NULL && strcmp(debug_env, "true") == 0;
    int code = run_with_oqs(argc, argv);
    debugf("exit status %d", code);
    return code;
}

int main(int argc, char **argv)
{
    return run(argc, argv);
}
