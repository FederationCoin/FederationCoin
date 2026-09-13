FederationCoin
==============

Setup
---------------------
FederationCoin is a new Blake2b UTXO chain for sending money. Fresh genesis, no inherited coins. Not Bitcoin. Not Knots. Not a CBDC. Experimental. No price promise. Confirmations stay weak until hashrate is expensive.

This tree is the node (`federationcoind`, `federationcoin-qt`, and related tools), based on Bitcoin Knots `v29.4.1.knots20260508`. **Main is not launched.** The default network is a placeholder. Mine and peer on **`-testnet`**.

Downloads and the constitution: [federationcoin.org](https://federationcoin.org). Testnet explorer: [mempool.federationcoin.org](https://mempool.federationcoin.org). Source: [github.com/FederationCoin/FederationCoin](https://github.com/FederationCoin/FederationCoin).

Running
---------------------
The following are some helpful notes on how to run FederationCoin on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/federationcoin-qt` (GUI) or
- `bin/federationcoind` (headless)

Add `-testnet` for the public test chain (P2P 35333, RPC 35332, HRP `tfcn`).

### Windows

Unpack the files into a directory, or use the installer, then run `federationcoin-qt.exe`. Use the Start Menu "Federation Coin (testnet)" shortcut, or `federationcoin-qt.exe -testnet`. See [README_windows.txt](README_windows.txt).

### macOS

Drag Federation Coin to your applications folder, and then run Federation Coin. Pass `-testnet` for the public test chain.

### Need Help?

* [federationcoin.org](https://federationcoin.org) — what this chain is, testnet, and how to build
* [mempool.federationcoin.org](https://mempool.federationcoin.org) — testnet explorer
* [FederationCoin/FederationCoin](https://github.com/FederationCoin/FederationCoin) — source, issues, and the tree README
* Build notes in this `doc/` directory (Unix, Windows, macOS)

Building
---------------------
The following are developer notes on how to build FederationCoin on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows-msvc.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)

Development
---------------------
This repo's [root README](/README.md) contains relevant information on the chain, dummy main vs testnet, and how we build.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://doxygen.bitcoincore.org/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Resources
* [federationcoin.org](https://federationcoin.org)
* [github.com/FederationCoin/FederationCoin](https://github.com/FederationCoin/FederationCoin) (`29.x-federationcoin`)

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [bitcoin.conf Configuration File](bitcoin-conf.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [Managing Wallets](managing-wallets.md)
- [Multisig Tutorial](multisig-tutorial.md)
- [Offline Signing Tutorial](offline-signing-tutorial.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [PSBT support](psbt.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
