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
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 1683
#define BUFFER_SIZE 4096
#define SIGNATURE_ALGORITHM LN_ML_DSA_87
#define SIGNATURE_LENGTH 4627
#define SIGNATURE_EXTENSION ".sig"
#define SIGNATURE_EXTENSION_LENGTH (sizeof(SIGNATURE_EXTENSION) - 1)
#define DIGEST_ALGORITHM LN_sha256
#define DIGEST_LENGTH 32
#define TLS_GROUP "MLKEM1024"
#define CMD_PREFIX_CHAR '\\'
#define EPOLL_MAX_EVENTS 2

bool is_debug = false;
bool is_newline = true;
bool is_error = false;

void ensure_newline(FILE *file)
{
    if (!is_newline)
    {
        putc('\n', file);
        is_newline = true;
    }
}

void print_errno(char *label)
{
    if (is_error)
    {
        return;
    }
    is_error = true;
    ensure_newline(stderr);
    perror(label);
}

void print_openssl_errors()
{
    if (is_error)
    {
        return;
    }
    is_error = true;
    ensure_newline(stderr);
    ERR_print_errors_fp(stderr);
}

void print_symbol(char symbol, int color)
{
    printf("\033[%dm", color);
    putchar(symbol);
    printf("\033[0m");
    putchar(' ');
}

void prompt()
{
    print_symbol('>', 94);
    fflush(stdout);
    is_newline = false;
}

void vflogf(FILE *file, const char *label, int color, const char *format, va_list args)
{
    ensure_newline(file);
    fprintf(file, "\033[%dm", color);
    fprintf(file, "[%s]", label);
    fprintf(file, "\033[0m");
    putc(' ', file);
    vfprintf(file, format, args);
    putc('\n', file);
}

void debugf(const char *format, ...)
{
    if (!is_debug)
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
    ensure_newline(stdout);
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

void eprintf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

EVP_PKEY *read_evp_pkey(char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        print_errno(path);
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if (pkey == NULL)
    {
        fclose(file);
        print_openssl_errors();
        return NULL;
    }
    if (fclose(file) != 0)
    {
        EVP_PKEY_free(pkey);
        print_errno("fclose");
        return NULL;
    }
    if (OBJ_ln2nid(EVP_PKEY_get0_type_name(pkey)) !=
        OBJ_ln2nid(SIGNATURE_ALGORITHM))
    {
        EVP_PKEY_free(pkey);
        eprintf("signature algorithm is not \"%s\"\n", SIGNATURE_ALGORITHM);
        return NULL;
    }
    return pkey;
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
        print_errno("fseek");
        return -1;
    }
    uint64_t len = ftell(file);
    if (len == -1)
    {
        print_errno("ftell");
        return -1;
    }
    if (fseek(file, 0, SEEK_SET) != 0)
    {
        print_errno("fseek");
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
    if (len != 1 && str[0] == '0')
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
        print_errno("malloc");
        return NULL;
    }
    char *type = strtok(buf, " ");
    c->type = cmd_type_from_str(type);
    if (c->type == -1)
    {
        OPENSSL_free(c);
        errorf("invalid command: %s", buf);
        return NULL;
    }
    size_t capacity = 4;
    c->args_len = 0;
    c->args = OPENSSL_malloc(capacity * sizeof(char *));
    if (c->args == NULL)
    {
        print_errno("malloc");
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
                print_errno("realloc");
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
    char *pathname_copy = OPENSSL_malloc(strlen(pathname) + 1);
    if (pathname_copy == NULL)
    {
        print_errno("malloc");
        return false;
    }
    strcpy(pathname_copy, pathname);
    file_store_item_t item = {.id = id, .pathname = pathname_copy};
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
        OPENSSL_free(fs->items[i].pathname);
        if (i != fs->size - 1)
        {
            memcpy(&fs->items[i], &fs->items[fs->size - 1], sizeof(file_store_item_t));
        }
        fs->size--;
        return true;
    }
    return false;
}

void file_store_free(file_store_t *fs)
{
    for (size_t i = 0; i < fs->size; i++)
    {
        OPENSSL_free(fs->items[i].pathname);
    }
    OPENSSL_free(fs);
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
    int epoll_fd;
    uint8_t upload_next_id;
    file_store_t *upload_store;
    file_store_t *download_store;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    EVP_MD_CTX *evp_md_ctx;
    EVP_MD *evp_md;
    EVP_PKEY_CTX *evp_pkey_ctx;
    EVP_PKEY *evp_pkey;
    EVP_SIGNATURE *evp_sig;
} peer_t;

bool peer_tcp_accept(peer_t *p)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        print_errno("socket");
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
        print_errno("setsockopt");
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
        print_errno("bind");
        close(server_fd);
        return false;
    }
    if (listen(server_fd, 1) == -1)
    {
        print_errno("listen");
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
        print_errno("accept");
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
        print_errno("socket");
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
        eprintf("invalid peer address: %s\n", p->addr);
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
        print_errno("close");
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
    p->ssl_ctx = ctx;
    if (SSL_CTX_set1_groups_list(ctx, TLS_GROUP) != 1)
    {
        return false;
    }
    if (SSL_CTX_set1_sigalgs_list(ctx, SIGNATURE_ALGORITHM) != 1)
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
        print_openssl_errors();
        return false;
    }
    return true;
}

bool peer_tls_write(peer_t *p, const void *buf, int n)
{
    if (SSL_write(p->ssl, buf, n) <= 0)
    {
        print_openssl_errors();
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
        print_openssl_errors();
        return false;
    }
    return true;
}

bool peer_tls_connect(peer_t *p)
{
    if (!peer_tls_init(p, TLS_client_method(), SSL_VERIFY_PEER, SSL_connect))
    {
        print_openssl_errors();
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
    SSL_CTX_free(p->ssl_ctx);
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

bool peer_epoll_init(peer_t *p)
{
    p->epoll_fd = epoll_create1(0);
    if (p->epoll_fd == -1)
    {
        print_errno("epoll_create1");
        return false;
    }
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = STDIN_FILENO;
    if (epoll_ctl(p->epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &event) == -1)
    {
        print_errno("epoll_ctl");
        return false;
    }
    event.data.fd = p->peer_fd;
    if (epoll_ctl(p->epoll_fd, EPOLL_CTL_ADD, p->peer_fd, &event) == -1)
    {
        print_errno("epoll_ctl");
        return false;
    }
    return true;
}

int peer_epoll_wait(peer_t *p, int fds[EPOLL_MAX_EVENTS])
{
    static struct epoll_event events[EPOLL_MAX_EVENTS];
    int n = epoll_wait(p->epoll_fd, events, 2, -1);
    if (n == -1)
    {
        print_errno("epoll_wait");
        return -1;
    }
    for (int i = 0; i < n; i++)
    {
        fds[i] = events[i].data.fd;
    }
    return n;
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
        print_errno(filename);
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
            print_errno("fwrite");
            fclose(file);
            return false;
        }
        if (size <= BUFFER_SIZE)
        {
            if (fclose(file) != 0)
            {
                print_errno("fclose");
                return false;
            }
            return true;
        }
        size -= BUFFER_SIZE;
    }
}

bool peer_read_file_sig(peer_t *p, char *filename)
{
    uint8_t *sig = OPENSSL_malloc(SIGNATURE_LENGTH);
    if (sig == NULL)
    {
        print_errno("malloc");
        return false;
    }
    if (!peer_tls_read(p, sig, SIGNATURE_LENGTH))
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
    if (fwrite(sig, 1, SIGNATURE_LENGTH, file) != SIGNATURE_LENGTH)
    {
        print_errno("fwrite");
        fclose(file);
        OPENSSL_free(sig);
        return false;
    }
    OPENSSL_free(sig);
    if (fclose(file) != 0)
    {
        print_errno("fclose");
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

bool peer_evp_init(peer_t *p)
{
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
    {
        print_openssl_errors();
        return false;
    }
    EVP_MD *md = EVP_MD_fetch(NULL, DIGEST_ALGORITHM, NULL);
    if (md == NULL)
    {
        EVP_MD_CTX_free(md_ctx);
        print_openssl_errors();
        return false;
    }
    EVP_PKEY *pkey = read_evp_pkey(p->sig_pkey);
    if (pkey == NULL)
    {
        EVP_MD_free(md);
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (pkey_ctx == NULL)
    {
        EVP_PKEY_free(pkey);
        EVP_MD_free(md);
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, SIGNATURE_ALGORITHM, NULL);
    if (sig == NULL)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_MD_free(md);
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    p->evp_md_ctx = md_ctx;
    p->evp_md = md;
    p->evp_pkey_ctx = pkey_ctx;
    p->evp_pkey = pkey;
    p->evp_sig = sig;
    return true;
}

uint8_t *peer_evp_digest(peer_t *p, FILE *file)
{
    if (EVP_DigestInit(p->evp_md_ctx, p->evp_md) != 1)
    {
        print_openssl_errors();
        return NULL;
    }
    uint8_t *buf = OPENSSL_malloc(BUFFER_SIZE);
    if (buf == NULL)
    {
        print_errno("malloc");
        return NULL;
    }
    while (true)
    {
        size_t n = fread(buf, 1, BUFFER_SIZE, file);
        if (ferror(file))
        {
            OPENSSL_free(buf);
            print_errno("fread");
            return NULL;
        }
        if (!peer_tls_write(p, buf, n) ||
            EVP_DigestUpdate(p->evp_md_ctx, buf, n) != 1)
        {
            OPENSSL_free(buf);
            print_openssl_errors();
            return NULL;
        }
        if (feof(file))
        {
            OPENSSL_free(buf);
            break;
        }
    }
    uint8_t *digest = OPENSSL_malloc(DIGEST_LENGTH);
    if (digest == NULL)
    {
        print_errno("malloc");
        return NULL;
    }
    if (EVP_DigestFinal(p->evp_md_ctx, digest, NULL) != 1)
    {
        OPENSSL_free(digest);
        print_openssl_errors();
        return NULL;
    }
    return digest;
}

uint8_t *peer_evp_sign(peer_t *p, uint8_t *digest)
{
    if (EVP_PKEY_sign_message_init(p->evp_pkey_ctx, p->evp_sig, NULL) != 1)
    {
        print_openssl_errors();
        return NULL;
    }
    uint8_t *sig = OPENSSL_malloc(SIGNATURE_LENGTH);
    if (sig == NULL)
    {
        print_errno("malloc");
        return NULL;
    }
    size_t sig_len = SIGNATURE_LENGTH;
    if (EVP_PKEY_sign(
            p->evp_pkey_ctx,
            sig,
            &sig_len,
            digest,
            DIGEST_LENGTH) != 1)
    {
        OPENSSL_free(sig);
        print_openssl_errors();
        return NULL;
    }
    return sig;
}

void peer_evp_free(peer_t *p)
{
    EVP_SIGNATURE_free(p->evp_sig);
    EVP_PKEY_free(p->evp_pkey);
    EVP_PKEY_CTX_free(p->evp_pkey_ctx);
    EVP_MD_free(p->evp_md);
    EVP_MD_CTX_free(p->evp_md_ctx);
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
        print_errno("malloc");
        return false;
    }
    if (!peer_tls_read(p, text, len))
    {
        OPENSSL_free(text);
        return false;
    }
    text[len] = '\0';
    putchar('\n');
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
        print_errno("malloc");
        return false;
    }
    if (!peer_tls_read(p, filename, len))
    {
        OPENSSL_free(filename);
        return false;
    }
    filename[len] = '\0';
    if (!file_store_add(p->download_store, id, filename))
    {
        OPENSSL_free(filename);
        return false;
    }
    commentf("%s (%d)", filename, id);
    OPENSSL_free(filename);
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
        print_errno(pathname);
        return false;
    }
    uint64_t size = get_file_size(file);
    if (size == -1 || !peer_write_uint64(p, size))
    {
        fclose(file);
        return false;
    }
    uint8_t *digest = peer_evp_digest(p, file);
    if (digest == NULL)
    {
        fclose(file);
        return false;
    }
    if (fclose(file) != 0)
    {
        OPENSSL_free(digest);
        print_errno("fclose");
        return false;
    }
    uint8_t *sig = peer_evp_sign(p, digest);
    if (sig == NULL)
    {
        OPENSSL_free(digest);
        return false;
    }
    OPENSSL_free(digest);
    if (!peer_tls_write(p, sig, SIGNATURE_LENGTH))
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

int peer_rx(peer_t *p)
{
    uint8_t mode;
    if (!peer_read_uint8(p, &mode))
    {
        return -1;
    }
    if (mode == MESSAGE_TEXT)
    {
        if (!peer_rx_text(p))
        {
            return -1;
        }
    }
    else if (mode == MESSAGE_UPLOAD)
    {
        if (!peer_rx_upload(p))
        {
            return -1;
        }
    }
    else if (mode == MESSAGE_DOWNLOAD)
    {
        if (!peer_rx_download(p))
        {
            return -1;
        }
    }
    else if (mode == MESSAGE_QUIT)
    {
        return 0;
    }
    return 1;
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

int peer_tx(peer_t *p)
{
    char buf[BUFFER_SIZE];
    if (fgets(buf, BUFFER_SIZE, stdin) == NULL)
    {
        print_errno("fgets");
        return -1;
    }
    is_newline = true;
    buf[strcspn(buf, "\n")] = '\0';
    if (buf[0] == CMD_PREFIX_CHAR)
    {
        cmd_t *cmd = cmd_parse(buf + 1);
        if (cmd == NULL)
        {
            return 1;
        }
        switch (cmd->type)
        {
        case CMD_TYPE_UPLOAD:
            if (!peer_tx_upload(p, cmd->args, cmd->args_len))
            {
                cmd_free(cmd);
                return -1;
            }
            break;
        case CMD_TYPE_DOWNLOAD:
            if (!peer_tx_download(p, cmd->args, cmd->args_len))
            {
                cmd_free(cmd);
                return -1;
            }
            break;
        case CMD_TYPE_HELP:
            printf("TODO\n");
            return 1;
        case CMD_TYPE_QUIT:
            cmd_free(cmd);
            if (!peer_write_uint8(p, MESSAGE_QUIT))
            {
                return -1;
            }
            else
            {
                return 0;
            }
        }
        cmd_free(cmd);
    }
    else if (!peer_tx_text(p, buf))
    {
        return -1;
    }
    return 1;
}

bool peer_init(
    peer_t *p,
    char *addr,
    char *cert,
    char *cert_pkey,
    char *ca_cert,
    char *sig_pkey)
{
    p->addr = addr;
    p->cert = cert;
    p->cert_pkey = cert_pkey;
    p->ca_cert = ca_cert;
    p->sig_pkey = sig_pkey;
    p->peer_fd = -1;
    p->server_fd = -1;
    p->epoll_fd = -1;
    p->upload_next_id = 0;
    p->upload_store = NULL;
    p->download_store = NULL;
    p->ssl_ctx = NULL;
    p->ssl = NULL;
    p->evp_md_ctx = NULL;
    p->evp_pkey = NULL;
    p->upload_store = file_store_new();
    if (p->upload_store == NULL)
    {
        return false;
    }
    p->download_store = file_store_new();
    if (p->download_store == NULL)
    {
        file_store_free(p->upload_store);
        return false;
    }
    if (!peer_evp_init(p))
    {
        file_store_free(p->download_store);
        file_store_free(p->upload_store);
        return false;
    }
    if (!peer_connect(p) && !peer_accept(p))
    {
        peer_evp_free(p);
        file_store_free(p->download_store);
        file_store_free(p->upload_store);
        return false;
    }
    if (!peer_epoll_init(p))
    {
        peer_tls_close(p);
        peer_tcp_close(p);
        peer_evp_free(p);
        file_store_free(p->download_store);
        file_store_free(p->upload_store);
        return false;
    }
    return true;
}

bool peer_run(peer_t *p)
{
    prompt();
    int fds[EPOLL_MAX_EVENTS];
    while (true)
    {
        int n = peer_epoll_wait(p, fds);
        if (n == -1)
        {
            return false;
        }
        for (int i = 0; i < n; i++)
        {
            int ok;
            if (fds[i] == STDIN_FILENO)
            {
                ok = peer_tx(p);
            }
            else if (fds[i] == p->peer_fd)
            {
                ok = peer_rx(p);
            }
            switch (ok)
            {
            case 1:
                prompt();
                continue;
            case 0:
                return true;
            case -1:
                return false;
            }
        }
    }
}

bool peer_free(peer_t *p)
{
    bool tls_ok = peer_tls_close(p);
    bool tcp_ok = peer_tcp_close(p);
    peer_evp_free(p);
    file_store_free(p->upload_store);
    file_store_free(p->download_store);
    return tls_ok && tcp_ok;
}

bool run(int argc, char **argv)
{
    if (argc != 6)
    {
        eprintf(
            "usage: %s <addr> <cert> <cert-pkey> <ca-cert> <sig-pkey>\n",
            argv[0]);
        return false;
    }
    char *addr = argv[1];
    char *cert = argv[2];
    char *cert_pkey = argv[3];
    char *ca_cert = argv[4];
    char *sig_pkey = argv[5];
    peer_t peer;
    if (!peer_init(&peer, addr, cert, cert_pkey, ca_cert, sig_pkey))
    {
        return false;
    }
    if (!peer_run(&peer))
    {
        peer_free(&peer);
        return false;
    }
    return peer_free(&peer);
}

int main(int argc, char **argv)
{
    char *debug_env = getenv("DEBUG");
    is_debug = debug_env != NULL && strcmp(debug_env, "true") == 0;
    int code = run(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE;
    debugf("exit status %d", code);
    return code;
}
