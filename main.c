#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>
#include <openssl/provider.h>
#include <openssl/err.h>

const char *PROVIDER_NAME = "oqsprovider";

int main()
{
    OQS_init();
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(OSSL_LIB_CTX_new(), PROVIDER_NAME);
    if (prov == NULL)
    {
        fprintf(stderr, "failed to load provider: %s\n", PROVIDER_NAME);
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    printf("hello, world!\n");
    OSSL_PROVIDER_unload(prov);
    OQS_destroy();
    return EXIT_SUCCESS;
}
