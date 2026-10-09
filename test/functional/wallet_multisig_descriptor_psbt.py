#!/usr/bin/env python3
# Copyright (c) 2021-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""wsh(sortedmulti) watch wallets are not a spend kind."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet_util import generate_keypair


class WalletMultisigDescriptorPSBTTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.assert_closed_address_types(node)
        descs = [d["desc"] for d in node.listdescriptors()["descriptors"]]
        assert not any(d.startswith("pkh(") for d in descs)
        assert not any("wsh(sortedmulti" in d for d in descs)
        _, pub = generate_keypair()
        wsh = descsum_create(f"wsh(sortedmulti(1,{pub.hex()}))")
        node.createwallet(wallet_name="wsh_watch", blank=True, descriptors=True, disable_private_keys=True)
        watch = node.get_wallet_rpc("wsh_watch")
        imported = watch.importdescriptors([{"desc": wsh, "timestamp": "now", "active": True, "internal": False}])[0]
        assert imported.get("success") or imported.get("error"), imported
        wallets = node.listwallets()
        default_name = "default_wallet" if "default_wallet" in wallets else wallets[0]
        default = node.get_wallet_rpc(default_name)
        for kind in ("mldsa87", "mldsa44", "secp"):
            assert default.validateaddress(default.getnewaddress("", kind))["isvalid"]


if __name__ == '__main__':
    WalletMultisigDescriptorPSBTTest(__file__).main()
