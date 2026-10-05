#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test node responses to invalid transactions.

In this test we connect to one node over p2p, and test tx requests."""
from decimal import Decimal

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.wallet import MiniWallet
from data import invalid_txs


HERITAGE_SCRIPT_TEMPLATES = {
    "InvalidOPIFConstruction",
    "TooManySigops",
    "NonStandardAndInvalid",
}


class InvalidTxRequestTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            "-acceptnonstdtxn=1",
        ]]
        self.setup_clean_chain = True

    def bootstrap_p2p(self, *, num_connections=1):
        """Add a P2P connection to the node.

        Helper to connect and wait for version handshake."""
        for i in range(num_connections):
            self.nodes[0].add_outbound_p2p_connection(P2PDataStore(), p2p_idx=i)

    def reconnect_p2p(self, **kwargs):
        """Tear down and bootstrap the P2P connection to the node.

        The node gets disconnected several times in this test. This helper
        method reconnects the p2p and restarts the network thread."""
        self.nodes[0].disconnect_p2ps()
        self.bootstrap_p2p(**kwargs)

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.bootstrap_p2p()

        best_block = self.nodes[0].getbestblockhash()
        tip = int(best_block, 16)
        best_block_time = self.nodes[0].getblock(best_block)['time']
        block_time = best_block_time + 1

        self.log.info("Create a new block whose coinbase is only used for structural invalid-tx templates.")
        height = 1
        block = create_block(tip, create_coinbase(height), block_time, height=height)
        block.solve()
        block1 = block
        node.p2ps[0].send_blocks_and_test([block], node, success=True)

        self.log.info("Mature the block.")
        self.generate(wallet, 100)

        for BadTxTemplate in invalid_txs.iter_all_templates():
            name = BadTxTemplate.__name__
            if name in HERITAGE_SCRIPT_TEMPLATES or name.startswith("DisabledOpcode"):
                self.log.info("Leaving heritage script template dark: %s", name)
                continue
            self.log.info("Testing invalid transaction: %s", name)
            template = BadTxTemplate(spend_block=block1)
            tx = template.get_tx()
            node.p2ps[0].send_txs_and_test(
                [tx], node, success=False,
                reject_reason=template.reject_reason,
            )

        self.reconnect_p2p(num_connections=2)

        self.log.info('Test orphan transaction handling ... ')
        withhold = wallet.create_self_transfer_multi(num_outputs=2, fee_per_output=12_000)
        tx_withhold = withhold['tx']

        orphan_1 = wallet.create_self_transfer_multi(utxos_to_spend=[withhold['new_utxos'][0]], num_outputs=3, fee_per_output=10_000)
        tx_orphan_1 = orphan_1['tx']

        no_fee_in = orphan_1['new_utxos'][0]
        tx_orphan_2_no_fee = wallet.create_self_transfer_multi(
            utxos_to_spend=[no_fee_in],
            amount_per_output=int(no_fee_in['value'] * COIN),
        )['tx']
        tx_orphan_2_valid = wallet.create_self_transfer(utxo_to_spend=orphan_1['new_utxos'][1], fee=Decimal("0.00012"))['tx']

        tx_orphan_2_invalid = CTransaction()
        bad = orphan_1['new_utxos'][2]
        tx_orphan_2_invalid.vin.append(CTxIn(outpoint=COutPoint(int(bad['txid'], 16), bad['vout'])))
        tx_orphan_2_invalid.vout.append(CTxOut(nValue=11 * COIN, scriptPubKey=wallet._scriptPubKey))
        tx_orphan_2_invalid.calc_sha256()

        self.log.info('Send the orphans ... ')
        node.p2ps[0].send_txs_and_test([tx_orphan_1, tx_orphan_2_no_fee, tx_orphan_2_valid], node, success=False)
        node.p2ps[1].send_txs_and_test([tx_orphan_2_invalid], node, success=False)

        assert_equal(0, node.getmempoolinfo()['size'])
        assert_equal(2, len(node.getpeerinfo()))

        self.log.info('Send the withhold tx ... ')
        with node.assert_debug_log(expected_msgs=["bad-txns-in-belowout"]):
            node.p2ps[0].send_txs_and_test([tx_withhold], node, success=True)

        expected_mempool = {
            t.hash
            for t in [
                tx_withhold,
                tx_orphan_1,
                tx_orphan_2_valid,
            ]
        }
        assert_equal(expected_mempool, set(node.getrawmempool()))

        self.log.info('Test orphan pool overflow')
        orphan_tx_pool = [CTransaction() for _ in range(101)]
        for i in range(len(orphan_tx_pool)):
            orphan_tx_pool[i].vin.append(CTxIn(outpoint=COutPoint(i, 333)))
            orphan_tx_pool[i].vout.append(CTxOut(nValue=11 * COIN, scriptPubKey=wallet._scriptPubKey))

        with node.assert_debug_log(['orphanage overflow, removed 1 tx']):
            node.p2ps[0].send_txs_and_test(orphan_tx_pool, node, success=False)

        self.log.info('Test orphan with rejected parents')
        rejected_parent = CTransaction()
        rejected_parent.vin.append(CTxIn(outpoint=COutPoint(tx_orphan_2_invalid.sha256, 0)))
        rejected_parent.vout.append(CTxOut(nValue=11 * COIN, scriptPubKey=wallet._scriptPubKey))
        rejected_parent.rehash()
        with node.assert_debug_log(['not keeping orphan with rejected parents {}'.format(rejected_parent.hash)]):
            node.p2ps[0].send_txs_and_test([rejected_parent], node, success=False)

        self.log.info('Test that a peer disconnection causes erase its transactions from the orphan pool')
        with node.assert_debug_log(['Erased 100 orphan transaction(s) from peer=']):
            self.reconnect_p2p(num_connections=1)

        self.log.info('Test that a transaction in the orphan pool is included in a new tip block causes erase this transaction from the orphan pool')
        until_a = wallet.create_self_transfer_multi(utxos_to_spend=[withhold['new_utxos'][1]], num_outputs=2, fee_per_output=12_000)
        tx_withhold_until_block_A = until_a['tx']
        tx_orphan_include_by_block_A = wallet.create_self_transfer(utxo_to_spend=until_a['new_utxos'][0], fee=Decimal("0.00012"))['tx']

        self.log.info('Send the orphan ... ')
        node.p2ps[0].send_txs_and_test([tx_orphan_include_by_block_A], node, success=False)

        tip = int(node.getbestblockhash(), 16)
        height = node.getblockcount() + 1
        block_A = create_block(tip, create_coinbase(height), height=height)
        block_A.vtx.extend([tx_withhold, tx_withhold_until_block_A, tx_orphan_include_by_block_A])
        add_witness_commitment(block_A)
        block_A.solve()

        self.log.info('Send the block that includes the previous orphan ... ')
        with node.assert_debug_log(["Erased 1 orphan transaction(s) included or conflicted by block"]):
            node.p2ps[0].send_blocks_and_test([block_A], node, success=True)
            node.syncwithvalidationinterfacequeue()

        self.log.info('Test that a transaction in the orphan pool conflicts with a new tip block causes erase this transaction from the orphan pool')
        until_b = wallet.create_self_transfer(utxo_to_spend=until_a['new_utxos'][1], fee=Decimal("0.00012"))
        tx_withhold_until_block_B = until_b['tx']
        include_b = wallet.create_self_transfer(utxo_to_spend=until_b['new_utxo'], fee=Decimal("0.00012"))
        tx_orphan_include_by_block_B = include_b['tx']
        tx_orphan_conflict_by_block_B = wallet.create_self_transfer(utxo_to_spend=until_b['new_utxo'], fee=Decimal("0.0002"))['tx']

        self.log.info('Send the orphan ... ')
        node.p2ps[0].send_txs_and_test([tx_orphan_conflict_by_block_B], node, success=False)

        tip = int(node.getbestblockhash(), 16)
        height = node.getblockcount() + 1
        block_B = create_block(tip, create_coinbase(height), height=height)
        block_B.vtx.extend([tx_withhold_until_block_B, tx_orphan_include_by_block_B])
        add_witness_commitment(block_B)
        block_B.solve()

        self.log.info('Send the block that includes a transaction which conflicts with the previous orphan ... ')
        with node.assert_debug_log(["Erased 1 orphan transaction(s) included or conflicted by block"]):
            node.p2ps[0].send_blocks_and_test([block_B], node, success=True)
            node.syncwithvalidationinterfacequeue()


if __name__ == '__main__':
    InvalidTxRequestTest(__file__).main()
