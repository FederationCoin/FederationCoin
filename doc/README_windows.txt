FederationCoin
=============

Intro
-----
FederationCoin is a new Blake2b UTXO chain for sending money. Fresh
genesis, no inherited coins. Not Bitcoin. Not Knots. Not a CBDC.
Experimental. No price promise. Confirmations stay weak until hashrate
is expensive.

This installer is the node: federationcoin-qt.exe (GUI) and the daemon
tools. It is based on Bitcoin Knots v29.4.1.knots20260508 and is
released under the MIT license.

Main is not launched. The default network is a placeholder. Mine and peer
on testnet.

Setup
-----
The installer puts the GUI in this folder. Run federationcoin-qt.exe.

For testing and exploration, use the "Federation Coin (testnet)" Start
Menu shortcut, or:

  federationcoin-qt.exe -testnet

Testnet uses P2P port 35333, RPC 35332, and address HRP tfcn.

Site:     https://federationcoin.org
Explorer: https://mempool.federationcoin.org
Source:   https://github.com/FederationCoin/FederationCoin

Default data directory: %LOCALAPPDATA%\FederationCoin
Config file: federationcoin.conf (an example is next to this readme).

Do not connect this node to Bitcoin or Knots. They are different
chains (different magic and ports). Dummy main uses P2P 4095 / RPC
4094 and is not the public chain.

The daemon folder
-----------------
  federationcoind.exe          headless node
  federationcoin-cli.exe       RPC client
  federationcoin-tx.exe        transaction utility
  federationcoin-wallet.exe    wallet tool
  test_federationcoin.exe      C++ unit-test runner (not a second node)
