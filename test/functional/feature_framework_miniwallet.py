#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test MiniWallet."""
import random
import string

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)


class FeatureFrameworkMiniWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def test_transfers_are_payments(self):
        """A run of payments is several transactions. None of them carry an OP_RETURN."""
        for mode_name, wallet in self.wallets:
            self.log.info(f"Test a chain of payments with MiniWallet mode {mode_name}...")
            chain = wallet.create_self_transfer_chain(chain_length=4)
            assert_equal(len(chain), 4)
            for tx in chain:
                assert tx['tx'].get_vsize() < 1200
                for vout in tx['tx'].vout:
                    assert len(vout.scriptPubKey) == 0 or vout.scriptPubKey[0] != 0x6a


    def test_wallet_tagging(self):
        """Verify that tagged wallet instances are able to send funds."""
        self.log.info("Test tagged wallet instances...")
        node = self.nodes[0]
        untagged_wallet = self.wallets[0][1]
        for i in range(10):
            tag = ''.join(random.choice(string.ascii_letters) for _ in range(20))
            self.log.debug(f"-> ({i}) tag name: {tag}")
            tagged_wallet = MiniWallet(node, tag_name=tag)
            untagged_wallet.send_to(from_node=node, scriptPubKey=tagged_wallet.get_output_script(), amount=10_000_000)
            tagged_wallet.rescan_utxos()
            tagged_wallet.send_self_transfer(from_node=node)
        self.generate(node, 1)  # clear mempool

    def run_test(self):
        node = self.nodes[0]
        # RAW_OP_TRUE / RAW_P2PK are heritage secp anyone-can-spend. Closed MiniWallet is ML-DSA-44.
        self.wallets = [
            ("ADDRESS_OP_TRUE", MiniWallet(node, mode=MiniWalletMode.ADDRESS_OP_TRUE)),
        ]
        for _, wallet in self.wallets:
            self.generate(wallet, 10)
        self.generate(wallet, COINBASE_MATURITY)

        self.test_transfers_are_payments()
        self.test_wallet_tagging()


if __name__ == '__main__':
    FeatureFrameworkMiniWalletTest(__file__).main()
