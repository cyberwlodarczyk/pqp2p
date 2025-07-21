# Post-Quantum P2P

## Introduction

pqp2p is a command-line chat that uses quantum-resistant cryptography to provide secure communication via direct tunnel between two peers and allows sending both text messages and files. It uses OpenSSL 3.5 to establish standard TLS connection but with post-quantum cryptographic algorithms: **ML-DSA** and **ML-KEM**. Because of the difficulties related to proper installation, compilation and configuration, dedicated Docker images have been made for development and testing. pqp2p requires two peers to have their own certificates signed by the same certificate authority. Additionally, files sent can be signed and then verified by the receiving peer using separate key pairs.

## Example

### Docker

Docker images for CA and peer have necessary binaries and files prepared and ready to use. **Disclaimer:** containers can and are intended to be run on different machines, but hosts have to be on the same network, because pqp2p does not implement mechanisms to handle communication behind NAT or over the internet.

```bash
# run docker container for the certificate authority
docker run -it cyberwlodarczyk/pqp2p:ca
# run docker container for the peer
docker run -it cyberwlodarczyk/pqp2p:peer
```

### [uguu.se](https://uguu.se/)

External service must be used in order to exchange signing requests, certificates and public keys. For testing and demonstration, simple and free file sharing services like [uguu.se](https://uguu.se/) are helpful.

```bash
# upload file
curl -F files[]=@data.txt https://uguu.se/upload
# download file
curl -o data.txt https://d.uguu.se/OlATWQRq
```

### Certificate Authority

CA must have its own certificate and private key files stored in configured paths. Then two signing requests from both peers have to be accepted.

```bash
# create private key and self-signed root certificate
openssl req -x509 -new -newkey ML-DSA-87 -keyout private/ca-key.pem -out certs/ca-cert.pem
# issue certificate based on signing request
openssl ca -in csr.pem -out cert.pem -cert certs/ca-cert.pem -keyfile private/ca-key.pem
```

### Peer

Each peer needs to create their own private key and certificate signing request. Moreover, separate key pair used for file signing has to be generated.

```bash
# create private key and certificate signing request
openssl req -new -newkey ML-DSA-87 -keyout key.pem -out csr.pem
# generate public-private key pair (method 1)
openssl genpkey -algorithm ML-DSA-87 -out sig-pkey.pem -outpubkey sig-pubkey.pem -aes-256-cbc
# generate public-private key pair (method 2)
pqkeygen sig-pkey.pem sig-pubkey.pem
# connect to remote peer
pqp2p 192.168.0.5 cert.pem key.pem ca-cert.pem sig-pkey.pem
# verify received file signature
pqverify data.txt data.txt.sig peer-sig-pubkey.pem
```
