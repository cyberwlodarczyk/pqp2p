# Post-Quantum P2P

## GCC

```bash
# compile and link with liboqs and openssl
gcc $CFLAGS $LDFLAGS -o main main.c -loqs -lcrypto -lssl
```

## OpenSSL

```bash
# create private key and self-signed root certificate for the certificate authority
openssl req -x509 -new -newkey dilithium3 -keyout ca-key.pem -out ca-cert.pem
# create private key and certificate signing request for the peer
openssl req -new -newkey dilithium3 -keyout key.pem -out csr.pem
# issue the certificate from the certificate authority
openssl ca -in csr.pem -out cert.pem -cert ca-cert.pem -keyfile ca-key.pem
# verify the certificate
openssl verify -CAfile ca-cert.pem cert.pem
```
