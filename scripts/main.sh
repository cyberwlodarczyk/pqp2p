#!/bin/ash
gcc -Wall $CFLAGS $LDFLAGS -o /bin/pqp2p src/main.c -lcrypto -lssl
