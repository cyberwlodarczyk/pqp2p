#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096
#define SIGNATURE_ALGORITHM LN_ML_DSA_87
#define SIGNATURE_LENGTH 4627
#define DIGEST_ALGORITHM LN_sha256
#define DIGEST_LENGTH 32

uint8_t *read_sig(char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        perror(path);
        return NULL;
    }
    uint8_t *sig = OPENSSL_malloc(SIGNATURE_LENGTH);
    if (sig == NULL)
    {
        fclose(file);
        perror("malloc");
        return NULL;
    }
    if (fread(
            sig,
            1,
            SIGNATURE_LENGTH,
            file) != SIGNATURE_LENGTH)
    {
        if (feof(file))
        {
            fprintf(stderr, "signature file is corrupted");
        }
        else if (ferror(file))
        {
            perror("fread");
        }
        OPENSSL_free(sig);
        fclose(file);
        return NULL;
    }
    if (fclose(file) != 0)
    {
        OPENSSL_free(sig);
        perror("fclose");
        return NULL;
    }
    return sig;
}

EVP_PKEY *read_pubkey(char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        perror(path);
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if (pkey == NULL)
    {
        fclose(file);
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    if (fclose(file) != 0)
    {
        EVP_PKEY_free(pkey);
        perror("fclose");
        return NULL;
    }
    if (OBJ_ln2nid(EVP_PKEY_get0_type_name(pkey)) !=
        OBJ_ln2nid(SIGNATURE_ALGORITHM))
    {
        EVP_PKEY_free(pkey);
        fprintf(
            stderr,
            "signature algorithm is not \"%s\"\n",
            SIGNATURE_ALGORITHM);
        return NULL;
    }
    return pkey;
}

typedef struct
{
    EVP_MD_CTX *md_ctx;
    EVP_MD *md;
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    EVP_SIGNATURE *sig;
} evp_t;

bool evp_init(evp_t *e, char *pubkey_path)
{
    e->md_ctx = EVP_MD_CTX_new();
    if (e->md_ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    e->md = EVP_MD_fetch(NULL, DIGEST_ALGORITHM, NULL);
    if (e->md == NULL)
    {
        EVP_MD_CTX_free(e->md_ctx);
        ERR_print_errors_fp(stderr);
        return false;
    }
    e->pkey = read_pubkey(pubkey_path);
    if (e->pkey == NULL)
    {
        EVP_MD_free(e->md);
        EVP_MD_CTX_free(e->md_ctx);
        return false;
    }
    e->pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, e->pkey, NULL);
    if (e->pkey_ctx == NULL)
    {
        EVP_PKEY_free(e->pkey);
        EVP_MD_free(e->md);
        EVP_MD_CTX_free(e->md_ctx);
        ERR_print_errors_fp(stderr);
        return false;
    }
    e->sig = EVP_SIGNATURE_fetch(NULL, SIGNATURE_ALGORITHM, NULL);
    if (e->sig == NULL)
    {
        EVP_PKEY_free(e->pkey);
        EVP_PKEY_CTX_free(e->pkey_ctx);
        EVP_MD_free(e->md);
        EVP_MD_CTX_free(e->md_ctx);
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

uint8_t *evp_digest(evp_t e, FILE *file)
{
    if (EVP_DigestInit(e.md_ctx, e.md) != 1)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    uint8_t *buf = OPENSSL_malloc(BUFFER_SIZE);
    if (buf == NULL)
    {
        perror("malloc");
        return NULL;
    }
    while (true)
    {
        size_t n = fread(buf, 1, BUFFER_SIZE, file);
        if (ferror(file))
        {
            OPENSSL_free(buf);
            perror("fread");
            return NULL;
        }
        if (EVP_DigestUpdate(e.md_ctx, buf, n) != 1)
        {
            OPENSSL_free(buf);
            ERR_print_errors_fp(stderr);
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
        perror("malloc");
        return NULL;
    }
    if (EVP_DigestFinal(e.md_ctx, digest, NULL) != 1)
    {
        OPENSSL_free(digest);
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    return digest;
}

int evp_verify(evp_t e, uint8_t *sig, uint8_t *digest)
{
    if (EVP_PKEY_verify_message_init(e.pkey_ctx, e.sig, NULL) != 1)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    switch (EVP_PKEY_verify(
        e.pkey_ctx,
        sig,
        SIGNATURE_LENGTH,
        digest,
        DIGEST_LENGTH))
    {
    case 1:
        return 1;
    case 0:
        return 0;
    default:
        ERR_print_errors_fp(stderr);
        return -1;
    }
}

void evp_free(evp_t e)
{
    EVP_SIGNATURE_free(e.sig);
    EVP_PKEY_free(e.pkey);
    EVP_PKEY_CTX_free(e.pkey_ctx);
    EVP_MD_free(e.md);
    EVP_MD_CTX_free(e.md_ctx);
}

bool run(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(
            stderr,
            "usage: %s <file> <signature> <pubkey>\n",
            argv[0]);
        return EXIT_FAILURE;
    }
    char *file_path = argv[1];
    char *sig_path = argv[2];
    char *pubkey_path = argv[3];
    evp_t evp;
    if (!evp_init(&evp, pubkey_path))
    {
        return false;
    }
    FILE *file = fopen(file_path, "rb");
    if (file == NULL)
    {
        evp_free(evp);
        perror(file_path);
        return false;
    }
    uint8_t *digest = evp_digest(evp, file);
    if (digest == NULL)
    {
        fclose(file);
        evp_free(evp);
        return false;
    }
    if (fclose(file) != 0)
    {
        OPENSSL_free(digest);
        evp_free(evp);
        perror("fclose");
        return false;
    }
    uint8_t *sig = read_sig(sig_path);
    if (sig == NULL)
    {
        OPENSSL_free(digest);
        evp_free(evp);
        return false;
    }
    int ok = evp_verify(evp, sig, digest);
    OPENSSL_free(sig);
    OPENSSL_free(digest);
    evp_free(evp);
    switch (ok)
    {
    case 1:
        printf("signature is valid\n");
        break;
    case 0:
        printf("signature is invalid\n");
        break;
    case -1:
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    return run(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE;
}
