#!/bin/ash
./scripts/gcc.sh || exit 1
cd .dev/bob
pqp2p 8889 127.0.0.1 8888 cert.pem key.pem ../ca/certs/cert.pem ../alice/public_key.pem private_key.pem
