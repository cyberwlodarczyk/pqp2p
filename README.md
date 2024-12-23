# Post-Quantum P2P

## GCC

```bash
gcc $CFLAGS $LDFLAGS -o main main.c -loqs -lcrypto -lssl
```

## OpenSSL

```bash
# create private key and self-signed root certificate for the certificate authority
openssl req -x509 -new -newkey dilithium3 -keyout private/ca-key.pem -out certs/ca-cert.pem
# create private key and certificate signing request for the peer
openssl req -new -newkey dilithium3 -keyout key.pem -out csr.pem
# issue the certificate from the certificate authority
openssl ca -in csr/peer-csr.pem -out newcerts/peer-cert.pem -cert certs/ca-cert.pem -keyfile private/ca-key.pem
# verify the certificate
openssl verify -CAfile ca-cert.pem cert.pem
```
