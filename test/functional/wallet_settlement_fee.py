#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Wallet send paths must refuse fees below floor(vsize / 12)."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


CHAIN_MINIMUM = "The chain has a minimum fee of 1 token per 12 vB"


class WalletSettlementFeeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-minrelaytxfee=0", "-mintxfee=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)
        dest = node.getnewaddress()

        assert_raises_rpc_error(-6, CHAIN_MINIMUM, node.sendtoaddress, dest, 1, "", "", False, True, None, "unset", False, 0)
        txid = node.sendtoaddress(dest, 1)
        assert txid

        raw = node.createrawtransaction([], [{dest: 1}])
        assert_raises_rpc_error(-4, CHAIN_MINIMUM, node.fundrawtransaction, raw, {"fee_rate": 0})
        funded = node.fundrawtransaction(raw)
        assert funded["fee"] > 0


if __name__ == "__main__":
    WalletSettlementFeeTest(__file__).main()
