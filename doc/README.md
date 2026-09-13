FederationCoin
==============

## For users

FederationCoin is a new Blake2b UTXO chain for sending money. Fresh genesis, no inherited coins. Not Bitcoin. Not Knots. Not a CBDC. Experimental. No price promise. Confirmations stay weak until hashrate is expensive.

This tree is the node (`federationcoind`, `federationcoin-qt`, and related tools). **Main is not launched.** The default network is a placeholder. Mine and peer on **`-testnet`** (P2P 35333, RPC 35332, HRP `tfcn`).

Downloads and the constitution: [federationcoin.org](https://federationcoin.org). Testnet explorer: [mempool.federationcoin.org](https://mempool.federationcoin.org). Source: [github.com/FederationCoin/FederationCoin](https://github.com/FederationCoin/FederationCoin).

### Running

#### Unix

Unpack the files into a directory and run:

- `bin/federationcoin-qt` (GUI) or
- `bin/federationcoind` (headless)

Add `-testnet` for the public test chain. Config file is `federationcoin.conf`. Datadir is `~/.federationcoin`.

#### Windows

Unpack the files into a directory, or use the installer, then run `federationcoin-qt.exe`. Use the Start Menu "Federation Coin (testnet)" shortcut, or `federationcoin-qt.exe -testnet`. See [README_windows.txt](README_windows.txt).

#### macOS

Drag Federation Coin to your applications folder, and then run Federation Coin. Pass `-testnet` for the public test chain.

### Need help?

* [federationcoin.org](https://federationcoin.org) — what this chain is, testnet, and how to build
* [mempool.federationcoin.org](https://mempool.federationcoin.org) — testnet explorer
* [FederationCoin/FederationCoin](https://github.com/FederationCoin/FederationCoin) — source, issues, and the tree README

## For developers

Based on Bitcoin Knots `v29.4.1.knots20260508` (`8c85b1585d`). Origin is `git@github.com:FederationCoin/FederationCoin.git`. Mainline is `29.x-federationcoin`. GitHub is detached from that fork; **never push** bitcoinknots. The [root README](/README.md) has dummy MAIN vs testnet, units, and Taproot parked.

### Building

These are developer notes on native builds, not complete guides.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows-msvc.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)

### Branching

Work on a branch off `29.x-federationcoin`. Open a same-repo pull request; a human merges. Do not push straight to mainline. Current work branch: `get-to-mainnet`. Knots pin `8c85b1585d` is unchanged.

### Release

Tags follow `vMAJOR.MINOR.PATCH.federationcoinYYYYMMDD` (optional `.<ext>`). Package may open a **draft** GitHub Release only. See golive notes in the workspace dump. The Knots-era [Release Process](release-process.md) doc is historical; do not treat it as our Package workflow.

### Quality

Code quality checks and metrics will be added over time.

### Development notes

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Source Code Documentation](https://github.com/FederationCoin/FederationCoin) (generate Doxygen locally; do not use Core hosted docs)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

The filename [bitcoin-conf.md](bitcoin-conf.md) is leftover; the node reads `federationcoin.conf`.

### Miscellaneous

- [Assets Attribution](assets-attribution.md)
- [bitcoin.conf Configuration File](bitcoin-conf.md) (file name is leftover; use `federationcoin.conf`)
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
