#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <oqs/oqs.h>

#define BUFFER_SIZE 4096
#define SIGNATURE_LENGTH OQS_SIG_dilithium_5_length_signature

uint8_t *read_signature(char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        perror(path);
        return NULL;
    }
    uint8_t *buf = OPENSSL_malloc(SIGNATURE_LENGTH);
    if (buf == NULL)
    {
        fclose(file);
        perror("malloc");
        return NULL;
    }
    if (fread(
            buf,
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
        OPENSSL_free(buf);
        fclose(file);
        return NULL;
    }
    if (fclose(file) != 0)
    {
        OPENSSL_free(buf);
        perror("fclose");
        return NULL;
    }
    return buf;
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
    return pkey;
}

typedef struct
{
    EVP_MD_CTX *md_ctx;
    EVP_MD *md;
    EVP_PKEY *pkey;
} evp_t;

bool evp_init(evp_t *e, char *pubkey_path)
{
    e->md_ctx = EVP_MD_CTX_new();
    if (e->md_ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    e->md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
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
    return true;
}

int evp_verify(evp_t e, FILE *file, uint8_t *sig)
{
    if (EVP_DigestVerifyInit(e.md_ctx, NULL, e.md, NULL, e.pkey) != 1)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    uint8_t *buf = OPENSSL_malloc(BUFFER_SIZE);
    if (buf == NULL)
    {
        perror("malloc");
        return -1;
    }
    while (true)
    {
        size_t n = fread(buf, 1, BUFFER_SIZE, file);
        if (ferror(file))
        {
            OPENSSL_free(buf);
            perror("fread");
            return -1;
        }
        if (EVP_DigestVerifyUpdate(e.md_ctx, buf, n) != 1)
        {
            OPENSSL_free(buf);
            ERR_print_errors_fp(stderr);
            return -1;
        }
        if (feof(file))
        {
            OPENSSL_free(buf);
            break;
        }
    }
    switch (EVP_DigestVerifyFinal(e.md_ctx, sig, SIGNATURE_LENGTH))
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
    EVP_PKEY_free(e.pkey);
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
    char *signature_path = argv[2];
    char *pubkey_path = argv[3];
    evp_t evp;
    if (!evp_init(&evp, pubkey_path))
    {
        return false;
    }
    uint8_t *signature = read_signature(signature_path);
    if (signature == NULL)
    {
        evp_free(evp);
        return false;
    }
    FILE *file = fopen(file_path, "rb");
    if (file == NULL)
    {
        OPENSSL_free(signature);
        evp_free(evp);
        perror(file_path);
        return false;
    }
    int ok = evp_verify(evp, file, signature);
    OPENSSL_free(signature);
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
        fclose(file);
        return false;
    }
    if (fclose(file) != 0)
    {
        perror("fclose");
        return false;
    }
    return true;
}

bool run_with_oqs_provider(int argc, char **argv)
{
    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (default_prov == NULL)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    OSSL_PROVIDER *oqs_prov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (oqs_prov == NULL)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    if (!run(argc, argv))
    {
        OSSL_PROVIDER_unload(default_prov);
        OSSL_PROVIDER_unload(oqs_prov);
        return false;
    }
    if (OSSL_PROVIDER_unload(default_prov) == 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    if (OSSL_PROVIDER_unload(oqs_prov) == 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    return run_with_oqs_provider(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE;
}
