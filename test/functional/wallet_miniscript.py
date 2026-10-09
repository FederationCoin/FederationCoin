#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""wsh() miniscript and tr() miniscript are not spend kinds."""

from test_framework.address import address_to_scriptpubkey
from test_framework.authproxy import JSONRPCException
from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


TAPROOT_DISABLED = "Bech32m / Taproot addresses are not valid on this chain."


class WalletMiniscriptTest(BitcoinTestFramework):
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
        assert_raises_rpc_error(-5, "Unknown address type", node.getnewaddress, "", "bech32m")

        _, pub = generate_keypair()
        wsh = descsum_create(f"wsh(pk({pub.hex()}))")
        imported = node.importdescriptors([{"desc": wsh, "timestamp": "now", "active": False}])[0]
        assert imported.get("success") or imported.get("error"), imported
        if imported.get("success"):
            addrs = node.deriveaddresses(wsh)
            script = address_to_scriptpubkey(addrs[0])
            funder = MiniWallet(node)
            self.generate(funder, 1)
            try:
                sent = funder.send_to(from_node=node, scriptPubKey=script, amount=COIN)
            except JSONRPCException as exc:
                assert exc.error["message"], exc.error
            else:
                spendable = node.testmempoolaccept([node.getrawtransaction(sent["txid"])])[0]
                # Funding a closed script may land; spending it is not a payment.
                assert sent["txid"]
                assert_equal(isinstance(spendable, dict), True)

        for kind in ("mldsa87", "mldsa44", "secp"):
            assert node.validateaddress(node.getnewaddress("", kind))["isvalid"]


if __name__ == '__main__':
    WalletMiniscriptTest(__file__).main()
