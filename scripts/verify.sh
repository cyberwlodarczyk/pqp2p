#!/bin/ash
gcc -Wall $CFLAGS $LDFLAGS -o /bin/pqverify src/verify.c -lcrypto
