#!/bin/ash
cd .dev/alice
pqp2p 127.0.0.1 cert.pem key.pem ../ca/certs/cert.pem  ../bob/public_key.pem private_key.pem
