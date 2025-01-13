#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <oqs/oqs.h>

int main(int argc, char **argv)
{

    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <public-key> <private-key>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *public_key_path = argv[1];
    const char *secret_key_path = argv[2];

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

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    FILE *private_key_file = NULL;
    FILE *public_key_file = NULL;

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "Dilithium5", NULL);
    if (pctx == NULL)
    {
        fprintf(stderr, "Błąd podczas tworzenia kontekstu EVP dla Dilithium5\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0)
    {
        fprintf(stderr, "Błąd inicjalizacji generowania klucza\n");
        return 1;
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        fprintf(stderr, "Błąd podczas generowania klucza\n");
        return 1;
    }

    private_key_file = fopen(secret_key_path, "wb");
    if (private_key_file == NULL)
    {
        fprintf(stderr, "Nie można otworzyć pliku na zapis klucza prywatnego\n");
        return 1;
    }
    if (PEM_write_PrivateKey(private_key_file, pkey, EVP_aes_256_cbc(), NULL, 0, NULL, NULL) == 0)
    {
        fprintf(stderr, "Błąd zapisu klucza prywatnego\n");
        return 1;
    }

    public_key_file = fopen(public_key_path, "wb");
    if (public_key_file == NULL)
    {
        fprintf(stderr, "Nie można otworzyć pliku na zapis klucza publicznego\n");
        return 1;
    }
    if (PEM_write_PUBKEY(public_key_file, pkey) == 0)
    {
        fprintf(stderr, "Błąd zapisu klucza publicznego\n");
        return 1;
    }

    fclose(private_key_file);
    fclose(public_key_file);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    OSSL_PROVIDER_unload(default_prov);
    OSSL_PROVIDER_unload(oqs_prov);

    printf("Klucze zostały zapisane do plików: private_key.pem i public_key.pem\n");
    return 0;
}
