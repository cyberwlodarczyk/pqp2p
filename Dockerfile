ARG ALPINE_VERSION=3.22
ARG OPENSSL_DIR=/opt/openssl
ARG OPENSSL_PATH=${OPENSSL_DIR}/bin
ARG OPENSSL_CONFIG=${OPENSSL_DIR}/ssl/openssl.cnf
ARG CFLAGS="-I${OPENSSL_DIR}/include"
ARG LDFLAGS="-L${OPENSSL_DIR}/lib -Wl,-rpath,${OPENSSL_DIR}/lib"
ARG PQP2P_OUT=/bin/pqp2p
ARG PQKEYGEN_OUT=/bin/pqkeygen
ARG PQVERIFY_OUT=/bin/pqverify

FROM alpine:${ALPINE_VERSION} AS build
ARG OPENSSL_DIR
ARG CFLAGS
ARG LDFLAGS
ARG PQP2P_OUT
ARG PQKEYGEN_OUT
ARG PQVERIFY_OUT
RUN apk add --no-cache build-base linux-headers make perl perl-utils perl-text-template git
WORKDIR /build
RUN git clone --depth 1 --branch openssl-3.5.0 https://github.com/openssl/openssl.git
WORKDIR /build/openssl
RUN ./Configure --prefix=${OPENSSL_DIR} "-Wl,-rpath,${OPENSSL_DIR}/lib64"
RUN make
RUN make test
RUN make install
RUN ln -s ${OPENSSL_DIR}/lib64 ${OPENSSL_DIR}/lib
WORKDIR /build/pqp2p
COPY src/* ./
RUN gcc -Wall ${CFLAGS} ${LDFLAGS} -o ${PQP2P_OUT} main.c -lcrypto -lssl
RUN gcc -Wall ${CFLAGS} ${LDFLAGS} -o ${PQKEYGEN_OUT} keygen.c -lcrypto
RUN gcc -Wall ${CFLAGS} ${LDFLAGS} -o ${PQVERIFY_OUT} verify.c -lcrypto

FROM alpine:${ALPINE_VERSION} AS dev
ARG OPENSSL_DIR
ARG OPENSSL_PATH
ARG CFLAGS
ARG LDFLAGS
COPY --from=build ${OPENSSL_DIR} ${OPENSSL_DIR}
RUN apk add --no-cache gcc libc-dev
ENV OPENSSL_DIR=${OPENSSL_DIR}
ENV CFLAGS=${CFLAGS}
ENV LDFLAGS=${LDFLAGS}
ENV PATH=${OPENSSL_PATH}:${PATH}

FROM alpine:${ALPINE_VERSION} AS ca
ARG OPENSSL_DIR
ARG OPENSSL_PATH
ARG OPENSSL_CONFIG
COPY --from=build ${OPENSSL_DIR} ${OPENSSL_DIR}
COPY openssl/ca.cnf ${OPENSSL_CONFIG}
RUN apk add --no-cache curl
ENV OPENSSL_DIR=${OPENSSL_DIR}
ENV PATH=${OPENSSL_PATH}:${PATH}
WORKDIR /home/ca
RUN adduser -D -h /home/ca ca
RUN mkdir certs newcerts private csr
RUN touch index.txt
RUN echo 1000 > serial
RUN chown -R ca:ca .
USER ca
CMD ["ash"]

FROM alpine:${ALPINE_VERSION} AS peer
ARG OPENSSL_DIR
ARG OPENSSL_PATH
ARG OPENSSL_CONFIG
ARG PQP2P_OUT
ARG PQKEYGEN_OUT
ARG PQVERIFY_OUT
COPY --from=build ${OPENSSL_DIR} ${OPENSSL_DIR}
COPY openssl/peer.cnf ${OPENSSL_CONFIG}
COPY --from=build ${PQP2P_OUT} ${PQP2P_OUT}
COPY --from=build ${PQKEYGEN_OUT} ${PQKEYGEN_OUT}
COPY --from=build ${PQVERIFY_OUT} ${PQVERIFY_OUT}
RUN apk add --no-cache curl
ENV OPENSSL_DIR=${OPENSSL_DIR}
ENV PATH=${OPENSSL_PATH}:${PATH}
WORKDIR /home/peer
RUN adduser -D -h /home/peer peer
RUN chown -R peer:peer .
USER peer
CMD ["ash"]
