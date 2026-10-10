#!/usr/bin/env python3
# Copyright (c) 2021-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Taproot / bech32m is not a spend kind."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair


TAPROOT_DISABLED = "Bech32m / Taproot addresses are not valid on this chain."


class WalletTaprootTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.assert_closed_address_types(node)
        assert_raises_rpc_error(-5, "Unknown address type", node.getnewaddress, "", "bech32m")
        _, pub = generate_keypair()
        desc = descsum_create(f"tr({pub.hex()})")
        imported = node.importdescriptors([{"desc": desc, "timestamp": "now"}])[0]
        if imported.get("success"):
            assert_raises_rpc_error(-5, TAPROOT_DISABLED, node.getnewaddress, "", "bech32m")
        else:
            assert imported.get("error"), imported
        for kind in ("mldsa87", "mldsa44", "secp"):
            assert node.validateaddress(node.getnewaddress("", kind))["isvalid"]


if __name__ == '__main__':
    WalletTaprootTest(__file__).main()
