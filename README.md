FederationCoin
==============

https://federationcoin.org

FederationCoin is a new Blake2b UTXO chain for sending money. Fresh genesis,
no inherited coins. Not Bitcoin. Not Knots. Not a CBDC. Confirmations stay
weak until hashrate is expensive. Experimental. No price promise.

## For users

This repository is the node: **`federationcoind`**, plus `federationcoin-cli`,
`federationcoin-qt`, and related tools.

**Main is not launched.** Default `federationcoind` (no flags) uses
placeholder genesis, magic (`00000000`), and ports (P2P **4095**, RPC
**4094**). The node prints a startup warning on default main. Those values
will be replaced at announcement. Do not mine default main as if it were
the product chain.

**Testnet is the public net.** `federationcoind -testnet` (P2P **35333**,
RPC **35332**, HRP `tfcn`). Explorer:
[mempool.federationcoin.org](https://mempool.federationcoin.org).

Testnet DNS seed hostname: `seed.testnet.federationcoin.org` (no records
yet). Until that name resolves, start one always-on `-testnet` node and
`addnode <ip>:35333 add`. Peers do not discover each other from zero.

Default datadir is `~/.federationcoin` (Windows:
`%LOCALAPPDATA%\FederationCoin`). Config file is `federationcoin.conf`.

The atomic unit is the **token**. **1 COIN = 100 million tokens**
(`COIN` in consensus). `MAX_MONEY` uses a 21 000 000 COIN
multiplier. COIN is not a ticker. Overlay token/asset protocols
(`-rejecttokens`) are unrelated to this native unit.

Taproot is **parked** on every network (`nStartTime = NEVER_ACTIVE`). Witness
v1 spends **hard-fail** (not anyone-can-spend). Bech32m / `fcn1p…` addresses
are not valid destinations while it is parked. This is not a post-quantum
script rewrite; tapscript code stays in the tree.

A Bitcoin or Knots node on 8333 is a different chain and must not appear as a
peer.

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

Released under the MIT license. See [COPYING](COPYING).

## For developers

Based on Bitcoin Knots `v29.4.1.knots20260508` (`8c85b1585d`); that parent is
pinned. Do not merge later Knots unless we re-open the pin. Origin is
`git@github.com:FederationCoin/FederationCoin.git`. Mainline is
`29.x-federationcoin`. GitHub is detached from that fork; **never push**
`upstream` (`bitcoinknots/bitcoin`).

Peer handshake uses `/Sumer:29.x/` (not Satoshi, not the product name).
Copyright headers and historical Bitcoin/Knots comments are left in place
on purpose.

### Clone and build

Use CMake (see [doc/build-unix.md](doc/build-unix.md) for dependencies). From
the source tree:

    cmake -B build -DBUILD_GUI=OFF
    cmake --build build -j$(nproc)

Binaries land in `build/bin/` (`federationcoind`, `federationcoin-cli`).

Platform notes: [doc/README.md](doc/README.md).

### Branching

Work on a branch off `29.x-federationcoin`. Open a same-repo pull request; a
human merges. Do not push straight to mainline. Current work branch for this
tree: `get-to-mainnet`. Knots pin `8c85b1585d` stays the ancestor gate.

### Release

`CLIENT_VERSION` in [CMakeLists.txt](CMakeLists.txt) is independent of git
tags. Tags (human, on origin mainline, before Package):

    vMAJOR.MINOR.PATCH.federationcoinYYYYMMDD
    vMAJOR.MINOR.PATCH.federationcoinYYYYMMDD.<ext>

Example: `v29.5.0.federationcoin20260913` or `.rc1`. The binary string may
still end with `.federation0`; that is not the git tag. Package may open a
**draft** GitHub Release only. No public Docker. Unsigned macOS and Windows.
Process: [golive notes](https://github.com/ldelarua/workspace-FederationCoin/blob/master/docs/golive-notes.md).

### Quality

Code quality checks and metrics will be added over time.
