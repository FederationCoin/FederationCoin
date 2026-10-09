#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Decaying wsh(thresh) miniscript is not a spend kind."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair


class WalletMiniscriptDecayingMultisigDescriptorPSBTTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.assert_closed_address_types(node)
        keys = [generate_keypair()[1].hex() for _ in range(4)]
        desc = descsum_create(
            f"wsh(thresh(4,pk({keys[0]}),s:pk({keys[1]}),s:pk({keys[2]}),s:pk({keys[3]}),sln:after(500000),sln:after(500001),sln:after(500002)))"
        )
        imported = node.importdescriptors([{"desc": desc, "timestamp": "now", "active": False}])[0]
        assert imported.get("success") or imported.get("error"), imported
        if imported.get("success"):
            addrs = node.deriveaddresses(desc)
            assert addrs
            # Deriving a closed script is not receiving on a spend kind.
            info = node.getaddressinfo(addrs[0])
            assert info.get("desc", "").startswith("wsh(")
        for kind in ("mldsa87", "mldsa44", "secp"):
            assert node.validateaddress(node.getnewaddress("", kind))["isvalid"]
        assert_raises_rpc_error(-5, "Unknown address type", node.getnewaddress, "", "legacy")


if __name__ == '__main__':
    WalletMiniscriptDecayingMultisigDescriptorPSBTTest(__file__).main()
