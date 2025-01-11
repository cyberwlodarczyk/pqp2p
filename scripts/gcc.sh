#!/bin/ash
gcc -Wall $CFLAGS $LDFLAGS -o /bin/pqp2p main.c -loqs -lcrypto -lssl
