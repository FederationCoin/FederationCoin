#!/usr/bin/env python3
# Copyright (c) 2015-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test node responses to invalid blocks.

In this test we connect to one node over p2p, and test block requests:
1) Valid blocks should be requested and become chain tip.
2) Invalid block with duplicated transaction should be re-requested.
3) Invalid block with bad coinbase value should be rejected and not
re-requested.
4) Invalid block due to future timestamp is later accepted when that timestamp
becomes valid.
"""
import copy
import time

from test_framework.blocktools import (
    MAX_FUTURE_BLOCK_TIME,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class InvalidBlockRequestTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PDataStore())
        wallet = MiniWallet(node)

        self.log.info("Mature MiniWallet coinbases")
        self.generate(wallet, 101)

        best_block = node.getblock(node.getbestblockhash())
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1

        self.log.info("Test merkle root malleability.")
        chain = wallet.create_self_transfer_chain(chain_length=2)
        tx1 = chain[0]['tx']
        tx2 = chain[1]['tx']
        block2_orig = create_block(tip, create_coinbase(height), block_time, txlist=[tx1, tx2], height=height)
        add_witness_commitment(block2_orig)
        block_time += 1
        block2_orig.solve()
        orig_hash = block2_orig.sha256

        # Header v2 commits to the transaction count, so a duplicated last
        # transaction no longer keeps the same block hash.
        block2 = create_block(tip, create_coinbase(height), block_time, txlist=[tx1, tx2, tx2], height=height)
        add_witness_commitment(block2)
        block2.solve()
        assert block2.sha256 != orig_hash
        assert block2_orig.vtx != block2.vtx

        peer.send_blocks_and_test([block2], node, success=False, reject_reason='bad-txns-duplicate')

        self.log.info("Test duplicate input block.")

        tx2_dup = copy.deepcopy(tx2)
        tx2_dup.vin.append(tx2_dup.vin[0])
        tx2_dup.rehash()
        block2_dup = create_block(tip, create_coinbase(height), block_time, txlist=[tx1, tx2_dup], height=height)
        add_witness_commitment(block2_dup)
        block2_dup.solve()
        peer.send_blocks_and_test([block2_dup], node, success=False, reject_reason='bad-txns-inputs-duplicate')

        self.log.info("Test very broken block.")

        block3 = create_block(tip, create_coinbase(height, nValue=100), block_time, height=height)
        block_time += 1
        block3.solve()

        peer.send_blocks_and_test([block3], node, success=False, reject_reason='bad-cb-amount')

        self.log.info("Test accepting original block after rejecting its mutated version.")
        peer.send_blocks_and_test([block2_orig], node, success=True, timeout=5)

        height += 1
        block_time += 1
        tip = int(block2_orig.hash, 16)

        self.log.info("Test inflation by duplicating input")
        tx3 = wallet.create_self_transfer(utxo_to_spend=chain[1]['new_utxo'])['tx']
        tx3.vin.append(tx3.vin[0])
        tx3.rehash()
        block4 = create_block(tip, create_coinbase(height), block_time, txlist=[tx3], height=height)
        add_witness_commitment(block4)
        block4.solve()
        peer.send_blocks_and_test([block4], node, success=False, reject_reason='bad-txns-inputs-duplicate')

        self.log.info("Test accepting identical block after rejecting it due to a future timestamp.")
        t = int(time.time())
        node.setmocktime(t)
        block = create_block(tip, create_coinbase(height), t + MAX_FUTURE_BLOCK_TIME + 1, height=height)
        block.solve()
        peer.send_blocks_and_test([block], node, force_send=True, success=False, reject_reason='time-too-new')
        node.setmocktime(t + 1)
        peer.send_blocks_and_test([block], node, success=True)


if __name__ == '__main__':
    InvalidBlockRequestTest(__file__).main()
