#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Previous-release BDB wallets are not a product load path."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BackwardsCompatibilityTest(BitcoinTestFramework):
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
        assert_equal(info["format"], "sqlite")


if __name__ == '__main__':
    BackwardsCompatibilityTest(__file__).main()
