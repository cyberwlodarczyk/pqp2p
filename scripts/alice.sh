#!/bin/ash
cd .dev/alice
pqp2p 127.0.0.1 cert.pem cert-pkey.pem ../ca/certs/cert.pem sig-pkey.pem
