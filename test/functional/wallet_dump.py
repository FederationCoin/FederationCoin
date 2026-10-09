#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""dumpwallet is a legacy-BDB command. Product wallets are descriptor-only."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


class WalletDumpTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.assert_legacy_wallet_refused(node)
        dump_path = node.datadir_path / "wallet.unencrypted.dump"
        assert_raises_rpc_error(-4, "Only legacy wallets are supported by this command", node.dumpwallet, str(dump_path))
        descs = [d["desc"] for d in node.listdescriptors()["descriptors"]]
        assert any(d.startswith("mldsa87(") for d in descs)
        assert any(d.startswith("mldsa(") for d in descs)
        assert any(d.startswith("wpkh(") for d in descs)


if __name__ == '__main__':
    WalletDumpTest(__file__).main()
