# Post-Quantum P2P

### OpenSSL

```bash
# create private key and self-signed root certificate for the certificate authority
openssl req -x509 -new -newkey dilithium5 -keyout ca-cert-pkey.pem -out ca-cert.pem
# create private key and certificate signing request for the peer
openssl req -new -newkey dilithium5 -keyout cert-pkey.pem -out csr.pem
# issue certificate from the certificate authority
openssl ca -in csr.pem -out cert.pem -cert ca-cert.pem -keyfile ca-cert-pkey.pem
# generate public-private key pair
openssl genpkey -algorithm dilithium5 -out sig-pkey.pem -outpubkey sig-pubkey.pem -aes256
# verify file signature
openssl pkeyutl -verify -pubin -inkey sig-pubkey.pem -in data.txt -sigfile data.txt.sig
```

### [file.io](https://www.file.io/)

```bash
# upload file
curl -F "file=@data.txt" https://file.io
# download file
curl -o data.txt https://file.io/BrEqbnMSLuHw
```
