#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Every non-coinbase transaction pays at least 3 tokens per virtual byte.
"""

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

MIN_TX_FEE_RATE = 3


class SettlementFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def block_with(self, node, tx):
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(int(tip, 16), create_coinbase(height),
                             ntime=node.getblockheader(tip)['time'] + 1,
                             txlist=[tx], height=height, header_v2=True)
        add_witness_commitment(block)
        block.solve()
        return block

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 110)

        unpaid = wallet.create_self_transfer(fee_rate=0)['tx']
        assert_equal(node.submitblock(self.block_with(node, unpaid).serialize().hex()), 'bad-txns-min-fee')

        paid = wallet.create_self_transfer(fee_rate=0)['tx']
        paid.vout[0].nValue -= MIN_TX_FEE_RATE * paid.get_vsize()
        paid.rehash()
        assert_equal(node.submitblock(self.block_with(node, paid).serialize().hex()), None)


if __name__ == '__main__':
    SettlementFeeTest(__file__).main()
