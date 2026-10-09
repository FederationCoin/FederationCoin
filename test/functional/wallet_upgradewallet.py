#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""upgradewallet targeted BDB format bumps. Product wallets are descriptor-only."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class UpgradeWalletTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.assert_legacy_wallet_refused(node)
        info = node.getwalletinfo()
        assert_equal(info["descriptors"], True)
        upgraded = node.upgradewallet()
        assert_equal(upgraded["previous_version"], upgraded["current_version"])
        assert "Already at latest version" in upgraded.get("result", "")


if __name__ == '__main__':
    UpgradeWalletTest(__file__).main()
