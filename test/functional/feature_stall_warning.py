#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tip older than 36 minutes logs a stall warning. The node does not exit."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet


class StallWarningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 1)
        tip_time = node.getblock(node.getbestblockhash())["time"]
        node.setmocktime(tip_time + 37 * 60)

        with node.assert_debug_log(["FederationCoin node: tip has stood still"]):
            info = node.getblockchaininfo()
        text = str(info["warnings"])
        assert "stood still" in text, text
        assert "36" in text or "37" in text, text
        # Still serving RPC: this is a warning, not a process error.
        assert node.getblockcount() >= 1

        self.generate(wallet, 1)
        after = node.getblockchaininfo()
        assert "stood still" not in str(after["warnings"]), after["warnings"]


if __name__ == "__main__":
    StallWarningTest(__file__).main()
