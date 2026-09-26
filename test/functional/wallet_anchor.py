#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

from test_framework.descriptors import descsum_create
from test_framework.messages import (
    COutPoint,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script_util import (
    ANCHOR_ADDRESS,
    PAY_TO_ANCHOR,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

class WalletAnchorTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_0_value_anchor_listunspent(self):
        self.log.info("Test that 0-value anchor outputs are detected as UTXOs")

        # Create an anchor output, and spend it
        sender = MiniWallet(self.nodes[0])
        anchor_tx = sender.create_self_transfer(fee_rate=0, version=3)["tx"]
        anchor_tx.vout.append(CTxOut(0, PAY_TO_ANCHOR))
        anchor_tx.rehash()  # Rehash after modifying anchor_tx
        anchor_spend = sender.create_self_transfer(version=3)["tx"]
        anchor_spend.vin.append(CTxIn(COutPoint(anchor_tx.sha256, 1), b""))
        anchor_spend.wit.vtxinwit.append(CTxInWitness())
        anchor_spend.rehash()  # Rehash after modifying anchor_spend
        submit_res = self.nodes[0].submitpackage([anchor_tx.serialize().hex(), anchor_spend.serialize().hex()])
        assert_equal(submit_res["package_msg"], "transaction failed")
        errors = " ".join(result.get("error", "") for result in submit_res["tx-results"].values())
        assert "bad-txns-vout-taproot-disabled" in errors, submit_res

    def test_cannot_sign_anchors(self):
        self.log.info("Test that the wallet cannot spend anchor outputs")
        for disable_privkeys in [False, True]:
            self.nodes[0].createwallet(wallet_name=f"anchor_spend_{disable_privkeys}", disable_private_keys=disable_privkeys)
            wallet = self.nodes[0].get_wallet_rpc(f"anchor_spend_{disable_privkeys}")
            if self.options.descriptors:
                import_res = wallet.importdescriptors([
                    {"desc": descsum_create(f"addr({ANCHOR_ADDRESS})"), "timestamp": "now"},
                    {"desc": descsum_create(f"raw({PAY_TO_ANCHOR.hex()})"), "timestamp": "now"}
                ])
                assert not import_res[0]["success"], import_res
                assert "Address is not valid" in import_res[0]["error"]["message"]
                assert_equal(import_res[1]["success"], disable_privkeys)
            else:
                wallet.importaddress(ANCHOR_ADDRESS)

        assert_raises_rpc_error(-5, "Invalid Bitcoin address", self.default_wallet.sendtoaddress, ANCHOR_ADDRESS, 1)

    def run_test(self):
        self.default_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.test_0_value_anchor_listunspent()
        self.test_cannot_sign_anchors()

if __name__ == '__main__':
    WalletAnchorTest(__file__).main()
