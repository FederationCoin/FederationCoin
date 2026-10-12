#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license.
"""BIP110/RDTS: header v2 is required from genesis; over-cap blocks are
rejected; a heavier invalid Blake2b-era branch still raises the peer-fork
warning. There is no SHA256d prefix to inherit or migrate.
"""
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.messages import CBlockHeader, CTxOut
from test_framework.script import CScript, OP_0
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

FORK_WARNING = "do not appear to fully agree with our peers"
NOT_IBD = '-maxtipage=100000000000'
PAY = CScript([OP_0, b"\x11" * 32])
REDUCED_DATA_MAX_BLOCK_WEIGHT = 2400000


class RdtsMigrationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]

    def setup_network(self):
        self.setup_nodes()

    def make_block(self, node, parent_hash, parent_time, height, *, v2=True, coinbase=None):
        if coinbase is None:
            coinbase = create_coinbase(height)
        block = create_block(int(parent_hash, 16), coinbase, ntime=parent_time + 1,
                             height=height, header_v2=v2)
        add_witness_commitment(block)
        block.solve()
        return block

    def submit_tip(self, node, *, time_offset=1):
        tip = node.getbestblockhash()
        blk = self.make_block(node, tip, node.getblockheader(tip)['time'] + time_offset - 1,
                              node.getblockcount() + 1, v2=True)
        assert_equal(node.submitblock(blk.serialize().hex()), None)
        return blk

    def has_fork_warning(self, node):
        return FORK_WARNING in ''.join(node.getblockchaininfo()['warnings'])

    def run_test(self):
        node = self.nodes[0]
        self.generatetoaddress(node, 20, node.get_deterministic_priv_key().address)

        self.log.info("A v1 header is rejected at submit")
        height = node.getblockcount() + 1
        tip = node.getbestblockhash()
        v1 = self.make_block(node, tip, node.getblockheader(tip)['time'], height, v2=False)
        assert_raises_rpc_error(
            -25, "bad-version-blake2b",
            lambda: node.submitheader(hexdata=CBlockHeader(v1).serialize().hex()),
        )

        self.log.info("A_CONTENT: over-cap Blake2b block is rejected at submit")
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        cb = create_coinbase(height)
        for _ in range(15000):
            cb.vout.append(CTxOut(0, PAY))
        cb.rehash()
        heavy = self.make_block(node, tip, node.getblockheader(tip)['time'], height, v2=True, coinbase=cb)
        assert_equal(node.submitblock(heavy.serialize().hex()), 'bad-blk-weight')
        assert heavy.get_weight() > REDUCED_DATA_MAX_BLOCK_WEIGHT
        assert_equal(node.getblockcount(), height - 1)

        self.log.info("A_WARNING: a genuinely invalid heavier Blake2b-era branch still warns")
        self.stop_node(0)
        self.start_node(0, extra_args=[NOT_IBD])
        for _ in range(12):
            self.submit_tip(node)
        node.invalidateblock(node.getblockhash(node.getblockcount() - 8))
        self.stop_node(0)
        self.start_node(0, extra_args=[NOT_IBD])
        self.submit_tip(node, time_offset=2)
        assert self.has_fork_warning(node), node.getblockchaininfo()['warnings']


if __name__ == '__main__':
    RdtsMigrationTest(__file__).main()
