#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Legacy-to-descriptor migratewallet is not a product path. BDB create is refused."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletMigrationTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.assert_legacy_wallet_refused(node)
        info = node.getwalletinfo()
        assert_equal(info["descriptors"], True)
        assert_equal(info["format"], "sqlite")
        try:
            node.migratewallet()
            raise AssertionError("migratewallet must not succeed on a descriptor wallet")
        except Exception as exc:
            if isinstance(exc, AssertionError):
                raise
            assert getattr(exc, "error", None) or str(exc)
        for kind in ("mldsa87", "mldsa44", "secp"):
            assert node.validateaddress(node.getnewaddress("", kind))["isvalid"]
        assert_raises_rpc_error(-5, "Unknown address type", node.getnewaddress, "", "legacy")


if __name__ == '__main__':
    WalletMigrationTest(__file__).main()
