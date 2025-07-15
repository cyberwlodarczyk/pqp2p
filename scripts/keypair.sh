#!/bin/ash
gcc -Wall $CFLAGS $LDFLAGS -o /bin/pqkeypair keypair.c -loqs -lcrypto -lssl
