#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <oqs/oqs.h>

#define SIGNATURE_ALGORITHM OQS_SIG_alg_dilithium_5

bool read_file(const char *file_path, uint8_t **buf, long *size)
{
    FILE *file = fopen(file_path, "r");
    if (file == NULL)
    {
        perror("Unable to open file\n");
        return false;
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    *buf = malloc(*size);
    if (*buf == NULL)
    {
        perror("Memory allocation failed\n");
        fclose(file);
        return false;
    }

    fread(*buf, 1, *size, file);
    fclose(file);

    return true;
}

bool peer_sig_init(char *public_key_path, uint8_t **PUBLIC_KEY, OQS_SIG *sig)
{

    FILE *public_key_file = fopen(public_key_path, "rb");
    if (!public_key_file)
    {
        perror("Failed to open key file");
        return false;
    }
    EVP_PKEY *public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);

    if (!public_key)
    {
        fprintf(stderr, "Error reading public key\n");
        ERR_print_errors_fp(stderr);
        return false;
    }

    uint8_t *pub_key = malloc(sig->length_public_key);

    size_t pub_key_len = sig->length_public_key;

    if (EVP_PKEY_get_raw_public_key(public_key, pub_key, &pub_key_len) <= 0)
    {
        fprintf(stderr, "Failed to extract raw keys\n");
        free(pub_key);
        EVP_PKEY_free(public_key);
        return false;
    }

    *PUBLIC_KEY = pub_key;

    EVP_PKEY_free(public_key);
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(stderr, "usage: %s <file> <signature> <public-key>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *file_path = argv[1];
    const char *signature_path = argv[2];
    char *public_key_path = argv[3];

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

    OQS_SIG *sig = OQS_SIG_new(SIGNATURE_ALGORITHM);

    if (sig == NULL)
    {
        fprintf(stderr, "Failed to initialize signature algorithm\n");
        return EXIT_FAILURE;
    }

    uint8_t *message = NULL;
    long message_len = 0;
    uint8_t *received_signature = NULL;
    long signature_len = 0;
    uint8_t *public_key = NULL;

    if (!read_file(file_path, &message, &message_len) ||
        !read_file(signature_path, &received_signature, &signature_len))
    {
        fprintf(stderr, "Failed to read files\n");
        OQS_SIG_free(sig);
        return EXIT_FAILURE;
    }

    if (!peer_sig_init(public_key_path, &public_key, sig))
    {
        fprintf(stderr, "Failed to initialize signature\n");
        free(received_signature);
        free(message);
        OQS_SIG_free(sig);
        return EXIT_FAILURE;
    }

    if (OQS_SIG_verify(sig, message, message_len, received_signature, signature_len, public_key) != OQS_SUCCESS)
    {
        fprintf(stderr, "Signature verification failed\n");
        free(received_signature);
        free(public_key);
        free(message);
        OQS_SIG_free(sig);
        return EXIT_FAILURE;
    }

    printf("Signature verification succeeded!\n");

    free(received_signature);
    free(public_key);
    free(message);
    OQS_SIG_free(sig);
    OSSL_PROVIDER_unload(default_prov);
    OSSL_PROVIDER_unload(oqs_prov);

    return EXIT_SUCCESS;
}
