ARG ALPINE_VERSION=3.21
ARG OPENSSL_DIR=/opt/openssl
ARG OPENSSL_MODULES=${OPENSSL_DIR}/lib/ossl-modules
ARG OPENSSL_PATH=${OPENSSL_DIR}/bin
ARG OPENSSL_CONFIG=${OPENSSL_DIR}/ssl/openssl.cnf
ARG LIBOQS_DIR=/opt/liboqs
ARG CFLAGS="-I${OPENSSL_DIR}/include -I${LIBOQS_DIR}/include"
ARG LDFLAGS="-L${OPENSSL_DIR}/lib -L${LIBOQS_DIR}/lib"
ARG PQP2P_OUT=/bin/pqp2p

FROM alpine:${ALPINE_VERSION} AS build
ARG OPENSSL_DIR
ARG OPENSSL_MODULES
ARG LIBOQS_DIR
ARG CFLAGS
ARG LDFLAGS
ARG PQP2P_OUT
RUN apk add --no-cache build-base linux-headers libtool automake autoconf cmake ninja make git
WORKDIR /build
RUN git clone --depth 1 --branch openssl-3.4.0 https://github.com/openssl/openssl.git
RUN git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
RUN git clone --depth 1 --branch 0.7.0 https://github.com/open-quantum-safe/oqs-provider.git
WORKDIR /build/openssl
RUN LDFLAGS="-Wl,-rpath -Wl,${OPENSSL_DIR}/lib64" ./config shared --prefix=${OPENSSL_DIR}
RUN make
RUN make install
RUN ln -s ${OPENSSL_DIR}/lib64 ${OPENSSL_DIR}/lib
WORKDIR /build/liboqs/build
RUN cmake -G"Ninja" -DOQS_DIST_BUILD=ON -DOPENSSL_ROOT_DIR=${OPENSSL_DIR} -DCMAKE_INSTALL_PREFIX=${LIBOQS_DIR} ..
RUN ninja
RUN ninja install
WORKDIR /build/oqs-provider
RUN liboqs_DIR=${LIBOQS_DIR} cmake -DOPENSSL_ROOT_DIR=${OPENSSL_DIR} -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=${OPENSSL_DIR} -S . -B build
RUN cmake --build build
RUN cmake --install build
RUN cp build/lib/oqsprovider.so ${OPENSSL_MODULES}
WORKDIR /build/pqp2p
COPY main.c .
RUN gcc ${CFLAGS} ${LDFLAGS} -o ${PQP2P_OUT} main.c -loqs -lcrypto -lssl

FROM alpine:${ALPINE_VERSION} AS dev
ARG OPENSSL_DIR
ARG OPENSSL_MODULES
ARG OPENSSL_PATH
ARG LIBOQS_DIR
ARG CFLAGS
ARG LDFLAGS
COPY --from=build ${OPENSSL_DIR} ${OPENSSL_DIR}
COPY --from=build ${LIBOQS_DIR} ${LIBOQS_DIR}
RUN apk add --no-cache gcc libc-dev
ENV OPENSSL_DIR=${OPENSSL_DIR}
ENV OPENSSL_MODULES=${OPENSSL_MODULES}
ENV LIBOQS_DIR=${LIBOQS_DIR}
ENV CFLAGS=${CFLAGS}
ENV LDFLAGS=${LDFLAGS}
ENV PATH=${OPENSSL_PATH}:${PATH}

FROM alpine:${ALPINE_VERSION} AS ca
ARG OPENSSL_DIR
ARG OPENSSL_PATH
ARG OPENSSL_CONFIG
COPY --from=build ${OPENSSL_DIR} ${OPENSSL_DIR}
COPY openssl/ca.cnf ${OPENSSL_CONFIG}
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
COPY --from=build ${OPENSSL_DIR} ${OPENSSL_DIR}
COPY openssl/peer.cnf ${OPENSSL_CONFIG}
COPY --from=build ${PQP2P_OUT} ${PQP2P_OUT}
ENV PATH=${OPENSSL_PATH}:${PATH}
WORKDIR /home/peer
RUN adduser -D -h /home/peer peer
RUN chown -R peer:peer .
USER peer
CMD ["ash"]