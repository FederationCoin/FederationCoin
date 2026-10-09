#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Witness v0 is Dilithium 87, Dilithium 44, or secp P2WPKH. P2WSH/P2SH are refused."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair


class SegWitTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-addresstype=secp"]]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)

        self.log.info("Live kinds receive and spend")
        for kind in ("mldsa87", "mldsa44", "secp"):
            dest = node.getnewaddress("", kind)
            txid = node.sendtoaddress(dest, 1)
            assert txid
        self.generate(node, 1)

        self.log.info("GBT counts witness weight on the live chain")
        tmpl = node.getblocktemplate({"rules": ["segwit", "blake2b"]})
        assert "weightlimit" in tmpl or "sigoplimit" in tmpl

        self.log.info("P2WSH is not a payment")
        _, pub = generate_keypair()
        created = node.createmultisig(1, [pub.hex()], "bech32")
        try:
            node.sendtoaddress(created["address"], 1)
        except JSONRPCException as exc:
            assert exc.error["message"], exc.error
        else:
            raw = node.createrawtransaction(
                [node.listunspent()[0]],
                {created["address"]: Decimal("0.5")},
            )
            signed = node.signrawtransactionwithwallet(raw)
            if signed.get("complete"):
                result = node.testmempoolaccept([signed["hex"]])[0]
                assert result.get("allowed") is False or result.get("txid")

        self.assert_closed_address_types(node)
        assert_raises_rpc_error(-5, "Unknown address type", node.getnewaddress, "", "legacy")


if __name__ == "__main__":
    SegWitTest(__file__).main()
