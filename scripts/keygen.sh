#!/bin/ash
gcc -Wall $CFLAGS $LDFLAGS -o /bin/pqkeygen src/keygen.c -lcrypto
