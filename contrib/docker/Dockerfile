FROM alpine:3.22 AS builder

RUN apk add --no-cache \
    build-base \
    cmake \
    boost-dev \
    libevent-dev \
    sqlite-dev \
    zeromq-dev \
    coreutils \
    binutils

WORKDIR /opt/federationcoin

COPY . .

WORKDIR /opt/federationcoin/build

RUN cmake .. \
    -DCMAKE_INSTALL_PREFIX="/usr/local/" \
    -DBUILD_DAEMON="ON" \
    -DBUILD_CLI="ON" \
    -DENABLE_WALLET="ON" \
    -DWITH_ZMQ="ON" \
    -DBUILD_TESTS="ON" \
    -DBUILD_GUI="OFF" \
    -DBUILD_TX="OFF" \
    -DBUILD_UTIL="OFF" \
    -DBUILD_WALLET_TOOL="OFF" \
    -DBUILD_BENCH="OFF" \
    -DBUILD_FUZZ_BINARY="OFF" \
    -DBUILD_UTIL_CHAINSTATE="OFF" \
    -DWITH_BDB="OFF" \
    -DWITH_USDT="OFF" \
    -DINSTALL_MAN="OFF" \
    -DWITH_CCACHE="OFF"

RUN cmake --build . --parallel $(nproc)
RUN ctest --output-on-failure
RUN cmake --install .

RUN strip --strip-unneeded /usr/local/bin/*

FROM alpine:3.22 AS final

ARG USER_ID=1000
ARG GROUP_ID=1000

RUN apk add --no-cache \
    libevent \
    sqlite-libs \
    zeromq \
    boost-system \
    boost-filesystem \
    boost-program_options

COPY --from=builder /usr/local/bin/federationcoind     /usr/local/bin/federationcoind
COPY --from=builder /usr/local/bin/federationcoin-cli  /usr/local/bin/federationcoin-cli

RUN addgroup -S -g ${GROUP_ID} federationcoin && \
    adduser -S -u ${USER_ID} -G federationcoin -H -s /bin/false federationcoin

WORKDIR /var/lib/federationcoind
EXPOSE 8333 8332
USER federationcoin
VOLUME ["/var/lib/federationcoind", "/etc/federationcoin/federationcoin.conf"]

ENTRYPOINT ["federationcoind", "-conf=/etc/federationcoin/federationcoin.conf", "-datadir=/var/lib/federationcoind"]

HEALTHCHECK --interval=5m --timeout=15s --start-period=2m --start-interval=10s \
    CMD ["federationcoin-cli", "-conf=/etc/federationcoin/federationcoin.conf", "-datadir=/var/lib/federationcoind", "getblockchaininfo"]
