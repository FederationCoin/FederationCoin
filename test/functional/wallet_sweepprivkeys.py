#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""sweepprivkeys targeted WIF/legacy scripts. Product wallets refuse that path."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class SweepPrivKeysTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.assert_legacy_wallet_refused(node)
        assert_equal(node.getwalletinfo()["descriptors"], True)
        assert_raises_rpc_error(-6, "No value to sweep", node.sweepprivkeys, {'privkeys': [], 'label': 'closed'})
        for kind in ("mldsa87", "mldsa44", "secp"):
            assert_equal(node.validateaddress(node.getnewaddress("", kind))["isvalid"], True)
        assert_raises_rpc_error(-5, "Unknown address type", node.getnewaddress, "", "legacy")


if __name__ == '__main__':
    SweepPrivKeysTest(__file__).main()
