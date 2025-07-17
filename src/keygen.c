#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>

typedef struct
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key;
} evp_t;

bool evp_init(evp_t *e)
{
    e->ctx = NULL;
    e->ctx = EVP_PKEY_CTX_new_from_name(NULL, "dilithium5", NULL);
    if (e->ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    if (EVP_PKEY_keygen_init(e->ctx) <= 0)
    {
        EVP_PKEY_CTX_free(e->ctx);
        ERR_print_errors_fp(stderr);
        return false;
    }
    e->key = NULL;
    if (EVP_PKEY_keygen(e->ctx, &e->key) <= 0)
    {
        EVP_PKEY_CTX_free(e->ctx);
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool evp_write(evp_t e, char *pkey_out, char *pubkey_out)
{
    FILE *pkey_file = fopen(pkey_out, "wb");
    if (pkey_file == NULL)
    {
        perror(pkey_out);
        return false;
    }
    if (PEM_write_PrivateKey(
            pkey_file,
            e.key,
            EVP_aes_256_cbc(),
            NULL,
            0,
            NULL,
            NULL) == 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    if (fclose(pkey_file) != 0)
    {
        perror("fclose");
        return false;
    }
    FILE *pubkey_file = fopen(pubkey_out, "wb");
    if (pubkey_file == NULL)
    {
        perror(pubkey_out);
        return false;
    }
    if (PEM_write_PUBKEY(pubkey_file, e.key) == 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    if (fclose(pubkey_file) != 0)
    {
        perror("fclose");
        return false;
    }
    return true;
}

void evp_free(evp_t e)
{
    EVP_PKEY_free(e.key);
    EVP_PKEY_CTX_free(e.ctx);
}

bool run(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <pkey-out> <pubkey-out>\n", argv[0]);
        return false;
    }
    char *pkey_out = argv[1];
    char *pubkey_out = argv[2];
    evp_t evp;
    if (!evp_init(&evp))
    {
        return false;
    }
    bool ok = evp_write(evp, pkey_out, pubkey_out);
    evp_free(evp);
    return ok;
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
