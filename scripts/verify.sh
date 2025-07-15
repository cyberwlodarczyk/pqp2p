#!/bin/ash
gcc -Wall $CFLAGS $LDFLAGS -o /bin/pqverify verify.c -loqs -lcrypto -lssl
