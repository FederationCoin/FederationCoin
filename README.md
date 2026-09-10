FederationCoin
==============

https://federationcoin.org

FederationCoin is a new Blake2b UTXO chain for sending money. Fresh genesis,
no inherited coins. Not Bitcoin. Not Knots. Not a CBDC. Confirmations stay
weak until hashrate is expensive. Experimental. No price promise.

This repository is the node: **`federationcoind`**, plus `federationcoin-cli`
and related tools. The default branch is `29.x-federationcoin`. Based on
Bitcoin Knots `v29.4.1.knots20260508` (`8c85b1585d`); that parent is pinned.

**Main is not launched.** Default `federationcoind` (no flags) uses
**placeholder** genesis, magic (`00000000`), and ports (P2P **4095**, RPC
**4094**). The node prints a startup warning on default main. Those values
will be replaced at announcement. Do not mine default main as if it were
the product chain. Mine and peer on **`-testnet`** for testing and
exploration (P2P **35333**, RPC **35332**, HRP `tfcn`).

Testnet DNS seed hostname: `seed.testnet.federationcoin.org` (no records
yet). Until that name resolves, start one always-on `-testnet` node and
`addnode <ip>:35333 add`. Peers do not discover each other from zero.

The atomic unit is the **token**. **1 COIN = 100 million tokens**
(`COIN` in consensus). `MAX_MONEY` uses a 21 000 000 COIN
multiplier. COIN is not a ticker. Overlay token/asset protocols
(`-rejecttokens`) are unrelated to this native unit.

Taproot is **parked** on every network (`nStartTime = NEVER_ACTIVE`). Witness
v1 spends **hard-fail** (not anyone-can-spend). Bech32m / `fcn1p…` addresses
are not valid destinations while it is parked. This is not a post-quantum
script rewrite; tapscript code stays in the tree.

Build
-----

Use CMake (see [doc/build-unix.md](doc/build-unix.md) for dependencies). From
the source tree:

    cmake -B build -DBUILD_GUI=OFF
    cmake --build build -j$(nproc)

Binaries land in `build/bin/` (`federationcoind`, `federationcoin-cli`).

Smoke
-----

Default datadir is `~/.federationcoin` (Windows: `%LOCALAPPDATA%\FederationCoin`).
Config file is `federationcoin.conf`.

Placeholder main (not launched; 0 peers unless you addnode):

    ./build/bin/federationcoind

Two local **testnet** nodes, generate, send (until DNS seeds exist):

    ./build/bin/federationcoind -testnet -datadir=/tmp/fc-a -port=35333 -rpcport=35332 -daemon
    ./build/bin/federationcoind -testnet -datadir=/tmp/fc-b -port=35335 -rpcport=35334 -daemon
    ./build/bin/federationcoin-cli -testnet -datadir=/tmp/fc-a addnode 127.0.0.1:35335 add
    ./build/bin/federationcoin-cli -testnet -datadir=/tmp/fc-a createwallet default
    ./build/bin/federationcoin-cli -testnet -datadir=/tmp/fc-b -rpcport=35334 createwallet default
    ADDR=$(./build/bin/federationcoin-cli -testnet -datadir=/tmp/fc-a getnewaddress)
    ./build/bin/federationcoin-cli -testnet -datadir=/tmp/fc-a generatetoaddress 101 "$ADDR"
    PAY=$(./build/bin/federationcoin-cli -testnet -datadir=/tmp/fc-b -rpcport=35334 getnewaddress)
    ./build/bin/federationcoin-cli -testnet -datadir=/tmp/fc-a -named sendtoaddress address="$PAY" amount=1 fee_rate=1
    ./build/bin/federationcoin-cli -testnet -datadir=/tmp/fc-a generatetoaddress 1 "$ADDR"

Regtest (instant blocks, local only):

    ./build/bin/federationcoind -regtest -datadir=/tmp/fc-rt -daemon

A Bitcoin or Knots node on 8333 is a different chain and must not appear as a
peer.

License
-------

Released under the MIT license. See [COPYING](COPYING). Copyright headers and
historical Bitcoin/Knots comments are left in place on purpose.

User agent
----------

Peer handshake uses `/Sumer:29.x/` (not Satoshi, not the product name).
