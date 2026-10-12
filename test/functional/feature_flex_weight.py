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
from test_framework.messages import CTxOut
from test_framework.script import CScript, OP_0
from test_framework.test_framework import BitcoinTestFramework


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
        self.num_nodes = 1
        self.setup_clean_chain = True

    def flexcap(self):
        return int(self.nodes[0].getblockchaininfo()["flexcap"])

    def make_weighted(self, target_weight):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        extra = CTxOut(0, FILLER)
        extra_wu = 4 * len(extra.serialize())
        pads = max(0, (target_weight - 2500 + extra_wu - 1) // extra_wu)
        cb = create_coinbase(height, nValue=50, halving_period=REGTEST_HALVING_INTERVAL)
        cb.vout.extend([CTxOut(0, FILLER) for _ in range(pads)])
        block = create_block(int(tip, 16), cb, ntime=node.getblockheader(tip)["time"] + 1,
                             height=height, header_v2=True)
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

        self.generate(node, REGTEST_HALVING_INTERVAL - 1)
        assert node.getblockcount() == REGTEST_HALVING_INTERVAL - 1
        assert self.flexcap() == MIN_CAP
        self.generate(node, 1)
        assert node.getblockcount() == REGTEST_HALVING_INTERVAL
        assert self.flexcap() == MIN_CAP, "a cut from the floor stays at the floor"

        pegged = REGTEST_HALVING_INTERVAL * 4 // 5
        for _ in range(pegged):
            result, weight = self.submit_weighted(PEGGED_WEIGHT)
            assert result is None, f"pegged block rejected: {result} weight={weight}"
            assert MIN_CAP - weight < 503, weight
        assert node.getblockcount() == REGTEST_HALVING_INTERVAL + pegged

        self.generate(node, REGTEST_HALVING_INTERVAL - pegged - 1)
        assert node.getblockcount() == 2 * REGTEST_HALVING_INTERVAL - 1
        assert self.flexcap() == MIN_CAP, "cap changes on the first block of the next epoch"

        result, weight = self.submit_weighted(FIT_AFTER_GROW)
        assert result is None, f"block that fits the grown cap rejected: {result} weight={weight}"
        assert node.getblockcount() == 2 * REGTEST_HALVING_INTERVAL
        assert self.flexcap() == GROWN_CAP

        result, weight = self.submit_weighted(OVER_GROWN)
        assert result is not None, f"expected reject over grown cap, weight={weight}"
        assert "weight" in result, result

        self.generate(node, REGTEST_HALVING_INTERVAL - 1)
        assert self.flexcap() == GROWN_CAP
        self.generate(node, 1)
        assert node.getblockcount() == 3 * REGTEST_HALVING_INTERVAL
        assert self.flexcap() == MIN_CAP, "slack for four fifths of an epoch cuts back to the floor"


if __name__ == "__main__":
    FlexWeightTest(__file__).main()
