#!/bin/ash
./scripts/gcc.sh || exit 1
cd .dev/alice
pqp2p 8888 127.0.0.1 8889 cert.pem key.pem ../ca/certs/cert.pem  ../bob/public_key.pem private_key.pem
