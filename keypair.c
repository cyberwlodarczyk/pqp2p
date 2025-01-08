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
int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <public-key> <private-key>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *public_key_path = argv[1];
    const char *secret_key_path = argv[2];

    OQS_SIG *sig = OQS_SIG_new(SIGNATURE_ALGORITHM);

    if (sig == NULL)
    {
        return EXIT_FAILURE;
    }

    // tworzenie kluczy
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) // Sprawdzenie tego, czy kluczy zostały stworzone
    {
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        return false;
    }
    printf("Kluczy zostały stworzone");

    // Zapisywanie klucza publicznego
    FILE *public_key_file = fopen(public_key_path, "wb");
    if (public_key_file == NULL)
    {
        perror("Failed to open public key file");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        return EXIT_FAILURE;
    }

    fwrite(public_key, 1, sig->length_public_key, public_key_file);
    fclose(public_key_file);

    // Zapisywanie klucza prywatnego
    FILE *private_key_file = fopen(secret_key_path, "wb");
    if (private_key_file == NULL)
    {
        perror("Failed to open private key file");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        return EXIT_FAILURE;
    }

    fwrite(secret_key, 1, sig->length_secret_key, private_key_file);
    fclose(private_key_file);

    printf("Keys saved successfully\n");

    // Zwolnienie zasobów
    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);

    return EXIT_SUCCESS;
}