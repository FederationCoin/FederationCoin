#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Witness v0 is the three spend kinds. P2WSH is not a payment."""

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

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)
        for kind in ("mldsa87", "mldsa44", "secp"):
            assert node.sendtoaddress(node.getnewaddress("", kind), 1)
        self.generate(node, 1)
        _, pub = generate_keypair()
        created = node.createmultisig(1, [pub.hex()], "bech32")
        try:
            node.sendtoaddress(created["address"], 1)
        except JSONRPCException as exc:
            assert exc.error["message"], exc.error
        self.assert_closed_address_types(node)
        assert_raises_rpc_error(-5, "Unknown address type", node.getnewaddress, "", "legacy")


if __name__ == '__main__':
    SegWitTest(__file__).main()
