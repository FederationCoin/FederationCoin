#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test reduced-data rules at the BLAKE2b fork height.

The rules turn on at the fork and do not expire. Both nodes enforce them.
"""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    add_witness_commitment,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_0,
    OP_DROP,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# RDTS activates at the BLAKE2b fork height (see -testactivationheight below)
ACTIVATION_HEIGHT = 432
# Consensus weight limits: the reduced one applies while RDTS is active
REDUCED_DATA_MAX_BLOCK_WEIGHT = 2400000
MAX_BLOCK_WEIGHT = 4000000
# Weight the assembler keeps free for the header and coinbase (-blockreservedweight)
DEFAULT_BLOCK_RESERVED_WEIGHT = 8000
# A witness element of this size is legal pre-RDTS (520-byte limit) and
# illegal under RDTS (256 bytes) unless the coin spent predates the fork.
VIOLATING_PUSH_SIZE = 300
# The first BLAKE2b block's coinbase must contain the headline; this value
class TemporaryDeploymentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Both nodes enforce reduced-data rules from the fork height. There is
        # no expiry.
        self.extra_args = [
            [f'-testactivationheight=blake2b@{ACTIVATION_HEIGHT}',
             '-acceptnonstdtxn=1'],
            [f'-testactivationheight=blake2b@{ACTIVATION_HEIGHT}',
             '-acceptnonstdtxn=1'],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def create_block_for_node(self, node, txs=None, time_offset=0):
        """Create a block for a specific node, v1 or v2 to match its height."""
        if txs is None:
            txs = []
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        tip_header = node.getblockheader(tip)
        block_time = tip_header['time'] + 1 + time_offset
        coinbase = create_coinbase(height)
        block = create_block(int(tip, 16), coinbase, ntime=block_time, txlist=txs,
                             height=height, header_v2=height >= ACTIVATION_HEIGHT)
        add_witness_commitment(block)
        block.solve()
        return block

    def mine_blocks_on_node(self, node, count):
        """Mine count blocks on a specific node."""
        for _ in range(count):
            block = self.create_block_for_node(node)
            node.submitblock(block.serialize().hex())

    def payment_chain(self, wallet, count):
        """count payments, each spending the previous. The block is heavy
        because it contains transactions, not a data script."""
        first = wallet.create_self_transfer()
        txs = [first["tx"]]
        stack = first["tx"].wit.vtxinwit[0].scriptWitness.stack
        tip = first["tx"]
        for _ in range(count - 1):
            child = CTransaction()
            child.vin = [CTxIn(COutPoint(tip.sha256, 0))]
            child.vout = [CTxOut(tip.vout[0].nValue - 1000, tip.vout[0].scriptPubKey)]
            child.wit.vtxinwit = [CTxInWitness()]
            child.wit.vtxinwit[0].scriptWitness.stack = stack
            child.rehash()
            txs.append(child)
            tip = child
        assert tip.vout[0].nValue > 0
        return txs

    def block_of_chain(self, node, wallet, count, extra=None):
        txs = self.payment_chain(wallet, count)
        if extra:
            txs = list(extra) + txs
        return self.create_block_for_node(node, txs)

    def chain_counts(self, node, wallet):
        """How many payments sit under the weight cap, and how many cross it."""
        if getattr(self, "_chain_counts", None):
            return self._chain_counts
        one = self.block_of_chain(node, wallet, 1).get_weight()
        two = self.block_of_chain(node, wallet, 2).get_weight()
        delta = two - one
        base = one - delta
        over = (REDUCED_DATA_MAX_BLOCK_WEIGHT - base) // delta + 2
        under = max(1, (REDUCED_DATA_MAX_BLOCK_WEIGHT - base) // delta - 2)
        self._chain_counts = (under, over)
        return self._chain_counts

    def create_block_of_weight(self, node, target_weight):
        """A block of exactly target_weight. The weight is payment outputs.

        Each output is at most 34 bytes. The boundary is four weight units,
        so the last output's script length lands on the target.
        """
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block_time = node.getblockheader(tip)['time'] + 1
        pay = CScript([OP_0, b'\x11' * 32])

        def build(num_full, last_len, short_by):
            coinbase = create_coinbase(height)
            scripts = [pay for _ in range(num_full)]
            if short_by and scripts:
                scripts[-1] = CScript(bytes(pay)[:-short_by])
            if last_len:
                scripts.append(CScript([OP_TRUE] * last_len))
            for script in scripts:
                coinbase.vout.append(CTxOut(0, script))
            coinbase.rehash()
            block = create_block(int(tip, 16), coinbase, ntime=block_time,
                                 height=height, header_v2=height >= ACTIVATION_HEIGHT)
            add_witness_commitment(block)
            return block

        base = build(0, 0, 0).get_weight()
        step = build(1, 0, 0).get_weight() - base
        num_full = max(0, (target_weight - base) // step)
        while build(num_full, 0, 0).get_weight() > target_weight:
            num_full -= 1
        while build(num_full + 1, 0, 0).get_weight() <= target_weight:
            num_full += 1
        block = None
        for last_len in range(0, 35):
            candidate = build(num_full, last_len, 0)
            if candidate.get_weight() == target_weight:
                block = candidate
                break
        if block is None and num_full:
            for short_by in range(1, 34):
                for last_len in range(1, 35):
                    candidate = build(num_full, last_len, short_by)
                    if candidate.get_weight() == target_weight:
                        block = candidate
                        break
                if block is not None:
                    break
        assert block is not None, target_weight
        block.solve()
        return block

    def create_tx_with_large_output(self, wallet):
        """Create a transaction with 84-byte OP_RETURN (violates BIP-110's 83-byte limit)."""
        tx_dict = wallet.create_self_transfer()
        tx = tx_dict['tx']
        # 81 bytes data = 84-byte script (OP_RETURN + OP_PUSHDATA1 + len + data)
        tx.vout.append(CTxOut(0, CScript([OP_RETURN, b'x' * 81])))
        tx.rehash()
        return tx

    def create_funding_and_violating_spend(self, wallet):
        """A funding transaction paying to a P2WSH script, and a spend of it
        whose witness carries a VIOLATING_PUSH_SIZE-byte element: valid
        pre-RDTS, invalid under RDTS (the coin is created at or after the
        fork height whenever the funding transaction is mined there, so the
        per-input grandfathering does not apply)."""
        witness_script = CScript([OP_DROP, OP_TRUE])
        funding = wallet.create_self_transfer()['tx']
        funding.vout[0] = CTxOut(funding.vout[0].nValue, script_to_p2wsh_script(witness_script))
        funding.rehash()
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(funding.sha256, 0))]
        spend.vout = [CTxOut(funding.vout[0].nValue - 1000, CScript([OP_TRUE]))]
        spend.wit.vtxinwit = [CTxInWitness()]
        spend.wit.vtxinwit[0].scriptWitness.stack = [b'\x42' * VIOLATING_PUSH_SIZE, witness_script]
        spend.rehash()
        return funding, spend

    def assert_block_rejected_for_push_size(self, node, block):
        result = node.submitblock(block.serialize().hex())
        assert result is not None and 'Push value size limit exceeded' in result, f"Expected push-size rejection, got: {result}"

    def rdts_active_for_next_block(self, node):
        """Whether the RDTS rules apply to the next block on node's tip."""
        info = node.getblockchaininfo()
        return info['blocks'] + 1 >= ACTIVATION_HEIGHT

    def assert_gbt_rdts(self, node, *, active):
        """Check getblocktemplate's RDTS surface: the rules entry and the
        advertised weight limit (external miners must see the real cap)."""
        # 'blake2b' is a client-capability rule: required once the template
        # is a v2 (BLAKE2b) header, ignored before the fork.
        tmpl = node.getblocktemplate({'rules': ['segwit', 'blake2b']})
        assert_equal('reduced_data' in tmpl['rules'], active)
        assert_equal(tmpl['weightlimit'],
                     REDUCED_DATA_MAX_BLOCK_WEIGHT if active else MAX_BLOCK_WEIGHT)

    def assert_rdts_deploymentinfo(self, node, *, active):
        """Check the reduced_data entry in getdeploymentinfo."""
        rd = node.getdeploymentinfo()['deployments']['reduced_data']
        assert_equal(rd['type'], 'flagday')
        assert_equal(rd['height'], ACTIVATION_HEIGHT)
        assert 'expiry_time' not in rd
        assert_equal(rd['active'], active)

    def run_test(self):
        node_bip110 = self.nodes[0]
        node_core = self.nodes[1]

        wallet = MiniWallet(node_bip110)

        # =====================================================================
        # Phase 1: Build the common pre-fork chain
        # =====================================================================
        self.log.info("Phase 1: Building the common pre-fork chain")

        self.log.info("Mining initial blocks for spendable coins...")
        # Each heavy block spends one mature coin and pays it forward.
        # Height 160 leaves about sixty of those coins spendable.
        self.generate(wallet, 160)
        self.sync_all()

        assert_equal(self.rdts_active_for_next_block(node_bip110), False)

        # RPC surface pre-fork: no rules entry, deployment reported inactive.
        self.assert_gbt_rdts(node_bip110, active=False)
        self.assert_rdts_deploymentinfo(node_bip110, active=False)
        self.assert_rdts_deploymentinfo(node_core, active=False)

        # Pre-fork only the 4M weight limit applies: a block over 800k still connects.
        under_count, over_count = self.chain_counts(node_bip110, wallet)
        heavy = self.block_of_chain(node_bip110, wallet, over_count)
        assert heavy.get_weight() > REDUCED_DATA_MAX_BLOCK_WEIGHT
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), None)
        self.sync_all()

        # Mine to two blocks before the fork height
        self.log.info("Mining to two blocks before the fork height...")
        self.generate(node_bip110, ACTIVATION_HEIGHT - 2 - node_bip110.getblockcount())
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 430)

        # Block 431 is outside the weight cap and the push-size rule. A user
        # OP_RETURN is rejected at every height, so it is not in this block.
        self.log.info("Test: block 431 (the last pre-fork block) is outside the weight cap")
        self.assert_gbt_rdts(node_bip110, active=False)
        self.assert_rdts_deploymentinfo(node_bip110, active=False)
        tx_invalid = self.create_tx_with_large_output(wallet)
        rejected = self.create_block_for_node(node_bip110, [tx_invalid])
        assert_equal(node_bip110.submitblock(rejected.serialize().hex()), 'bad-txns-datacarrier')
        funding, spend = self.create_funding_and_violating_spend(wallet)
        heavy = self.block_of_chain(node_bip110, wallet, over_count, extra=[funding, spend])
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), None)
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 431)

        # Block 432 (the fork block) is under every RDTS rule: the RPC surface
        # says so at tip 431, and each violation alone rejects the block. The
        # violating spend uses a coin created in the same block, so it is not
        # grandfathered. Disconnected: blocks failing only in ConnectBlock
        # are relayed (compact blocks) before full validation, and the other
        # node would adopt them.
        self.log.info("Test: block 432 (the fork block) is under every RDTS rule")
        self.disconnect_nodes(0, 1)
        self.assert_gbt_rdts(node_bip110, active=True)
        self.assert_rdts_deploymentinfo(node_bip110, active=True)
        heavy = self.block_of_chain(node_bip110, wallet, over_count)
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), 'bad-blk-weight-reduced_data')
        tx_invalid = self.create_tx_with_large_output(wallet)
        block = self.create_block_for_node(node_bip110, [tx_invalid])
        assert_equal(node_bip110.submitblock(block.serialize().hex()), 'bad-txns-vout-script-toolarge')
        funding, spend = self.create_funding_and_violating_spend(wallet)
        self.assert_block_rejected_for_push_size(node_bip110, self.create_block_for_node(node_bip110, [funding, spend]))
        assert_equal(node_bip110.getblockcount(), 431)
        self.connect_nodes(0, 1)

        # =====================================================================
        # Phase 2: Test activation and chain split
        # =====================================================================
        self.log.info("Phase 2: Testing activation and chain split behavior")

        # Mine block 432 (the BLAKE2b fork block: RDTS activates here)
        self.mine_blocks_on_node(node_bip110, 1)
        self.sync_all()
        assert_equal(node_bip110.getblockcount(), 432)
        assert_equal(self.rdts_active_for_next_block(node_bip110), True)
        self.log.info("Block 432 mined: the deployment is active")

        # RPC surface post-fork: rules entry present, deployment reported active.
        self.assert_gbt_rdts(node_bip110, active=True)
        self.assert_rdts_deploymentinfo(node_bip110, active=True)

        self.log.info("Disconnecting nodes before the invalid block...")
        self.disconnect_nodes(0, 1)

        self.log.info("Test: both nodes reject a block with an 84-byte OP_RETURN")
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_invalid = self.create_block_for_node(node_bip110, [tx_invalid])
        assert_equal(node_bip110.submitblock(block_invalid.serialize().hex()), 'bad-txns-vout-script-toolarge')
        assert_equal(node_core.submitblock(block_invalid.serialize().hex()), 'bad-txns-vout-script-toolarge')
        assert_equal(node_bip110.getblockcount(), 432)
        assert_equal(node_core.getblockcount(), 432)

        self.connect_nodes(0, 1)
        self.log.info("Both nodes extend a valid chain and stay together")
        for i in range(5):
            block = self.create_block_for_node(node_bip110, time_offset=i+10)
            node_bip110.submitblock(block.serialize().hex())
        self.sync_blocks()
        assert_equal(node_core.getbestblockhash(), node_bip110.getbestblockhash())
        assert_equal(node_bip110.getblockcount(), 437)

        # =====================================================================
        # Phase 3b: the RDTS weight limit
        # =====================================================================
        self.log.info("Phase 3b: 800k WU limit enforced while the deployment is active")
        heavy = self.block_of_chain(node_bip110, wallet, over_count)
        assert heavy.get_weight() > REDUCED_DATA_MAX_BLOCK_WEIGHT
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), 'bad-blk-weight-reduced_data')
        under = self.block_of_chain(node_bip110, wallet, under_count)
        assert under.get_weight() <= REDUCED_DATA_MAX_BLOCK_WEIGHT
        assert_equal(node_bip110.submitblock(under.serialize().hex()), None)
        # The boundary itself: exactly 800,000 WU connects, 800,004 does not.
        over = self.create_block_of_weight(node_bip110, REDUCED_DATA_MAX_BLOCK_WEIGHT + 4)
        assert_equal(node_bip110.submitblock(over.serialize().hex()), 'bad-blk-weight-reduced_data')
        exact = self.create_block_of_weight(node_bip110, REDUCED_DATA_MAX_BLOCK_WEIGHT)
        assert_equal(node_bip110.submitblock(exact.serialize().hex()), None)
        self.sync_all()
        self.log.info("  oversize rejected, under-cap accepted, exact boundary pinned")

        # A post-fork coin whose spend violates the push-size rule; kept for
        # the expiry boundary below.
        funding, post_fork_spend = self.create_funding_and_violating_spend(wallet)
        block = self.create_block_for_node(node_bip110, [funding])
        assert_equal(node_bip110.submitblock(block.serialize().hex()), None)
        self.sync_all()

        # =====================================================================
        # Phase 3c: block assembly under the reduced limit
        # =====================================================================
        self.log.info("Phase 3c: the assembler stays within the reduced limit")
        for _ in range(30):
            wallet.send_self_transfer_multi(from_node=node_bip110, num_outputs=600)
        assert node_bip110.getmempoolinfo()['bytes'] * 4 > REDUCED_DATA_MAX_BLOCK_WEIGHT
        tmpl = node_bip110.getblocktemplate({'rules': ['segwit', 'blake2b']})
        tmpl_weight = sum(tx['weight'] for tx in tmpl['transactions'])
        assert 500000 < tmpl_weight <= REDUCED_DATA_MAX_BLOCK_WEIGHT - DEFAULT_BLOCK_RESERVED_WEIGHT, tmpl_weight
        mined = node_bip110.getblock(self.generate(node_bip110, 1, sync_fun=self.no_op)[0])
        assert 500000 < mined['weight'] <= REDUCED_DATA_MAX_BLOCK_WEIGHT, mined['weight']
        self.sync_all()
        self.log.info(f"  template {tmpl_weight} WU, mined block {mined['weight']} WU")

        # =====================================================================
        # Phase 4: a far-future clock does not turn the rules off
        # =====================================================================
        self.log.info("Phase 4: rules stay on after the clock moves")
        node_bip110.setmocktime(2000000000)
        node_core.setmocktime(2000000000)
        self.generate(node_bip110, 12)
        self.sync_all()
        assert_equal(self.rdts_active_for_next_block(node_bip110), True)
        self.assert_gbt_rdts(node_bip110, active=True)
        self.assert_rdts_deploymentinfo(node_bip110, active=True)
        tx_invalid = self.create_tx_with_large_output(wallet)
        block_invalid = self.create_block_for_node(node_bip110, [tx_invalid])
        assert_equal(node_bip110.submitblock(block_invalid.serialize().hex()), 'bad-txns-vout-script-toolarge')
        heavy = self.block_of_chain(node_bip110, wallet, over_count)
        assert_equal(node_bip110.submitblock(heavy.serialize().hex()), 'bad-blk-weight-reduced_data')
        self.assert_block_rejected_for_push_size(node_bip110, self.create_block_for_node(node_bip110, [post_fork_spend]))

        assert 'Unknown new rules' not in ''.join(node_bip110.getblockchaininfo()['warnings'])
        self.log.info("Rules still enforced after the clock moved")


if __name__ == '__main__':
    TemporaryDeploymentTest(__file__).main()
