#!/bin/ash
gcc -Wall $CFLAGS $LDFLAGS -o /bin/pqverify src/verify.c -loqs -lcrypto -lssl
