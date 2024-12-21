ARG ALPINE_VERSION=3.21
ARG OPENSSL_DIR=/opt/openssl
ARG LIBOQS_DIR=/opt/liboqs

FROM alpine:${ALPINE_VERSION} AS build
ARG OPENSSL_DIR
ARG LIBOQS_DIR
RUN apk add --no-cache build-base linux-headers libtool automake autoconf cmake ninja make git
WORKDIR /build
RUN git clone --depth 1 --branch openssl-3.4.0 https://github.com/openssl/openssl.git
RUN git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
RUN git clone --depth 1 --branch 0.7.0 https://github.com/open-quantum-safe/oqs-provider.git
WORKDIR /build/openssl
RUN LDFLAGS="-Wl,-rpath -Wl,${OPENSSL_DIR}/lib" ./config shared --prefix=${OPENSSL_DIR}
RUN make
RUN make install
RUN if [ -d ${OPENSSL_DIR}/lib64 ]; then ln -s ${OPENSSL_DIR}/lib64 ${OPENSSL_DIR}/lib; fi
RUN if [ -d ${OPENSSL_DIR}/lib ]; then ln -s ${OPENSSL_DIR}/lib ${OPENSSL_DIR}/lib64; fi
WORKDIR /build/liboqs/build
RUN cmake -G"Ninja" -DOQS_DIST_BUILD=ON -DOPENSSL_ROOT_DIR=${OPENSSL_DIR} -DCMAKE_INSTALL_PREFIX=${LIBOQS_DIR} ..
RUN ninja
RUN ninja install
WORKDIR /build/oqs-provider
RUN liboqs_DIR=${LIBOQS_DIR} cmake -DOPENSSL_ROOT_DIR=${OPENSSL_DIR} -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=${OPENSSL_DIR} -S . -B build
RUN cmake --build build
RUN cmake --install build
RUN cp build/lib/oqsprovider.so ${OPENSSL_DIR}/lib/ossl-modules

FROM alpine:${ALPINE_VERSION}
ARG OPENSSL_DIR
ARG LIBOQS_DIR
COPY --from=build ${OPENSSL_DIR} ${OPENSSL_DIR}
COPY --from=build ${LIBOQS_DIR} ${LIBOQS_DIR}
RUN apk add --no-cache gcc libc-dev
ENV OPENSSL_DIR=${OPENSSL_DIR}
ENV OPENSSL_MODULES="${OPENSSL_DIR}/lib/ossl-modules"
ENV LIBOQS_DIR=${LIBOQS_DIR}
ENV PATH="${OPENSSL_DIR}/bin:${PATH}"
ENV CFLAGS="-I${OPENSSL_DIR}/include -I${LIBOQS_DIR}/include"
ENV LDFLAGS="-L${OPENSSL_DIR}/lib -L${LIBOQS_DIR}/lib"