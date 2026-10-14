#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Flex weight cap: floor 2,400,000, pegged blocks grow it, slack blocks cut it."""

from test_framework.blocktools import (
    REGTEST_HALVING_INTERVAL,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.messages import CBlockHeader, CInv, CTxOut, MSG_BLOCK, msg_getdata
from test_framework.p2p import P2PDataStore, P2PInterface
from test_framework.script import CScript, OP_0
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


MIN_CAP = 2400000
GROWN_CAP = 3600000
FILLER = CScript([OP_0, b"\x11" * 32])
OVER_WEIGHT = MIN_CAP + 10000
FIT_AFTER_GROW = 3_000_000
OVER_GROWN = GROWN_CAP + 10000
# Remaining room under 503 is pegged. Aim at the cap; the builder trims
# an overshoot of one payment, which stays inside that hole.
PEGGED_WEIGHT = MIN_CAP


class FlexWeightTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.setup_nodes()

    def flexcap(self):
        return int(self.nodes[0].getblockchaininfo()["flexcap"])

    def make_weighted(self, target_weight, *, tip=None, height=None, ntime=None):
        node = self.nodes[0]
        if tip is None:
            tip = node.getbestblockhash()
        if height is None:
            height = node.getblockcount() + 1
        if ntime is None:
            ntime = node.getblockheader(tip)["time"] + 1
        prev = int(tip, 16) if isinstance(tip, str) else tip
        extra = CTxOut(0, FILLER)
        extra_wu = 4 * len(extra.serialize())
        pads = max(0, (target_weight - 2500 + extra_wu - 1) // extra_wu)
        cb = create_coinbase(height, nValue=50, halving_period=REGTEST_HALVING_INTERVAL)
        cb.vout.extend([CTxOut(0, FILLER) for _ in range(pads)])
        block = create_block(prev, cb, ntime=ntime, height=height, header_v2=True)
        add_witness_commitment(block)
        while block.get_weight() < target_weight:
            more = max(1, (target_weight - block.get_weight() + extra_wu - 1) // extra_wu)
            # Commitment is the last output; drop it, pad, rebuild.
            block.vtx[0].vout.pop()
            block.vtx[0].vout.extend([CTxOut(0, FILLER) for _ in range(more)])
            add_witness_commitment(block)
        while block.get_weight() > target_weight and len(block.vtx[0].vout) > 2:
            block.vtx[0].vout.pop()
            block.vtx[0].vout.pop()
            add_witness_commitment(block)
        block.solve()
        return block

    def submit_weighted(self, target_weight):
        block = self.make_weighted(target_weight)
        return self.nodes[0].submitblock(block.serialize().hex()), block.get_weight()

    def run_test(self):
        node = self.nodes[0]
        assert self.flexcap() == MIN_CAP

        result, weight = self.submit_weighted(OVER_WEIGHT)
        assert result is not None, f"expected overweight reject, weight={weight}"
        assert "weight" in result, result

        self.generate(node, REGTEST_HALVING_INTERVAL - 1, sync_fun=self.no_op)
        assert node.getblockcount() == REGTEST_HALVING_INTERVAL - 1
        assert self.flexcap() == MIN_CAP
        self.generate(node, 1, sync_fun=self.no_op)
        assert node.getblockcount() == REGTEST_HALVING_INTERVAL
        assert self.flexcap() == MIN_CAP, "a cut from the floor stays at the floor"

        pegged = REGTEST_HALVING_INTERVAL * 4 // 5
        for _ in range(pegged):
            result, weight = self.submit_weighted(PEGGED_WEIGHT)
            assert result is None, f"pegged block rejected: {result} weight={weight}"
            assert MIN_CAP - weight < 503, weight
        assert node.getblockcount() == REGTEST_HALVING_INTERVAL + pegged

        self.generate(node, REGTEST_HALVING_INTERVAL - pegged - 1, sync_fun=self.no_op)
        assert node.getblockcount() == 2 * REGTEST_HALVING_INTERVAL - 1
        assert self.flexcap() == MIN_CAP, "cap changes on the first block of the next epoch"

        result, weight = self.submit_weighted(FIT_AFTER_GROW)
        assert result is None, f"block that fits the grown cap rejected: {result} weight={weight}"
        assert node.getblockcount() == 2 * REGTEST_HALVING_INTERVAL
        assert self.flexcap() == GROWN_CAP
        grown_hash = node.getblockhash(2 * REGTEST_HALVING_INTERVAL)

        # Header-only parent: a grown child must not be marked permanently invalid.
        parent = self.make_weighted(FIT_AFTER_GROW)
        child = self.make_weighted(FIT_AFTER_GROW, tip=parent.hash, height=node.getblockcount() + 2,
                                   ntime=parent.nTime + 1)
        node.submitheader(hexdata=CBlockHeader(parent).serialize().hex())
        orphan = node.submitblock(child.serialize().hex())
        assert orphan != "duplicate-invalid", orphan
        assert orphan is None or "weight" not in orphan, orphan
        assert node.submitblock(parent.serialize().hex()) is None
        child_again = node.submitblock(child.serialize().hex())
        assert child_again is None or child_again == "duplicate", child_again
        assert_equal(self.flexcap(), GROWN_CAP)

        # Restart must republish the admit bound so a grown-cap block still arrives.
        self.restart_node(0)
        peer = node.add_p2p_connection(P2PDataStore())
        p2p_block = self.make_weighted(FIT_AFTER_GROW)
        peer.send_blocks_and_test([p2p_block], node, success=True)
        node.disconnect_p2ps()

        result, weight = self.submit_weighted(OVER_GROWN)
        assert result is not None, f"expected reject over grown cap, weight={weight}"
        assert "weight" in result, result

        self.generate(node, 3 * REGTEST_HALVING_INTERVAL - node.getblockcount() - 1, sync_fun=self.no_op)
        assert self.flexcap() == GROWN_CAP
        self.generate(node, 1, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 3 * REGTEST_HALVING_INTERVAL)
        assert self.flexcap() == MIN_CAP, "slack for four fifths of an epoch cuts back to the floor"

        self.log.info("Serve a historical grown block after the tip has shrunk")
        historical = P2PInterface()
        node.add_p2p_connection(historical)
        historical.send_message(msg_getdata([CInv(MSG_BLOCK, int(grown_hash, 16))]))
        historical.wait_for_block(int(grown_hash, 16))
        node.disconnect_p2ps()

        # IBD from a short no-grow fork onto a chain that grew then shrank.
        # Admit is per-block, so the grown historical block still connects.
        self.generate(self.nodes[1], 10, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getblockcount(), 10)
        assert_equal(int(self.nodes[1].getblockchaininfo()["flexcap"]), MIN_CAP)
        self.connect_nodes(1, 0)
        self.sync_blocks()
        assert_equal(self.nodes[1].getblockcount(), node.getblockcount())
        assert_equal(int(self.nodes[1].getblockchaininfo()["flexcap"]), MIN_CAP)

        # Reindex of a chain that already grew must accept the post-grow blocks.
        self.restart_node(0, extra_args=["-reindex"])
        assert_equal(node.getblockcount(), 3 * REGTEST_HALVING_INTERVAL)
        assert_equal(self.flexcap(), MIN_CAP)


if __name__ == "__main__":
    FlexWeightTest(__file__).main()
