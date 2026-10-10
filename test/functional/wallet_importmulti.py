#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""importmulti is a legacy-BDB RPC. Product wallets use importdescriptors."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class ImportMultiTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.assert_legacy_wallet_refused(node)
        assert_equal(node.getwalletinfo()["descriptors"], True)
        assert_raises_rpc_error(-4, "Only legacy wallets are supported by this command", node.importmulti, [])
        descs = [d["desc"] for d in node.listdescriptors()["descriptors"]]
        assert any(d.startswith("mldsa87(") for d in descs)


if __name__ == '__main__':
    ImportMultiTest(__file__).main()
