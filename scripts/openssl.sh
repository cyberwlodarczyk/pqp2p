#!/bin/ash
rm -rf .dev
mkdir .dev
cd .dev
mkdir ca alice bob
cd ca
export HOME=$PWD
mkdir certs newcerts private
touch index.txt
echo 1000 >serial
openssl req -config ../../openssl/ca.cnf -x509 -new -newkey dilithium3 -keyout private/key.pem -out certs/cert.pem -subj "/C=PL/CN=CA" -noenc -batch
cd ../alice
openssl req -config ../../openssl/peer.cnf -new -newkey dilithium3 -keyout key.pem -out csr.pem -subj "/C=PL/CN=Alice" -noenc -batch
openssl ca -config ../../openssl/ca.cnf -in csr.pem -out cert.pem -cert ../ca/certs/cert.pem -keyfile ../ca/private/key.pem -batch
cd ../bob
openssl req -config ../../openssl/peer.cnf -new -newkey dilithium3 -keyout key.pem -out csr.pem -subj "/C=PL/CN=Bob" -noenc -batch
openssl ca -config ../../openssl/ca.cnf -in csr.pem -out cert.pem -cert ../ca/certs/cert.pem -keyfile ../ca/private/key.pem -batch
