#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP65 (CHECKLOCKTIMEVERIFY).

Test that the CHECKLOCKTIMEVERIFY soft-fork activates.
"""

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    SEQUENCE_FINAL,
    msg_block,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

CLTV_HEIGHT = 111


class BIP65Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True
        self.extra_args = [[
            f'-testactivationheight=cltv@{CLTV_HEIGHT}',
            '-acceptnonstdtxn=1',  # cltv_invalidate is nonstandard
        ]]
        self.setup_clean_chain = True
        self.rpc_timeout = 480

    def test_cltv_info(self, *, is_active):
        assert_equal(self.nodes[0].getdeploymentinfo()['deployments']['bip65'], {
                "active": is_active,
                "height": CLTV_HEIGHT,
                "type": "buried",
            },
        )

    def run_test(self):
        peer = self.nodes[0].add_p2p_connection(P2PInterface())
        wallet = MiniWallet(self.nodes[0])

        self.test_cltv_info(is_active=False)

        self.log.info("Mining %d blocks", CLTV_HEIGHT - 2)
        self.generate(wallet, 10)
        self.generate(self.nodes[0], CLTV_HEIGHT - 2 - 10)
        assert_equal(self.nodes[0].getblockcount(), CLTV_HEIGHT - 2)

        tip = self.nodes[0].getbestblockhash()
        block_time = self.nodes[0].getblockheader(tip)['mediantime'] + 1
        block = create_block(int(tip, 16), create_coinbase(CLTV_HEIGHT - 1), block_time, version=3, height=CLTV_HEIGHT - 1)
        block.solve()
        self.test_cltv_info(is_active=False)
        peer.send_and_ping(msg_block(block))
        self.test_cltv_info(is_active=True)
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)

        self.log.info("Test that blocks must now be at least version 4")
        tip = block.sha256
        block_time += 1
        block = create_block(tip, create_coinbase(CLTV_HEIGHT), block_time, version=3, height=CLTV_HEIGHT)
        block.solve()

        with self.nodes[0].assert_debug_log(expected_msgs=[f'{block.hash}, bad-version(0x00000003)']):
            peer.send_and_ping(msg_block(block))
            assert_equal(int(self.nodes[0].getbestblockhash(), 16), tip)
            peer.sync_with_ping()

        self.log.info("nLockTime is the live lock; OP_CLTV is not a spend")
        spendtx = wallet.create_self_transfer()['tx']
        spendtx.vin[0].nSequence = SEQUENCE_FINAL - 1
        spendtx.nLockTime = CLTV_HEIGHT + 50
        wallet.sign_tx(spendtx)
        assert_raises_rpc_error(-26, "non-final", self.nodes[0].sendrawtransaction, spendtx.serialize().hex(), 0)

        spendtx.nLockTime = CLTV_HEIGHT - 1
        wallet.sign_tx(spendtx)
        block = create_block(tip, create_coinbase(CLTV_HEIGHT), block_time + 1, version=4, txlist=[spendtx], height=CLTV_HEIGHT)
        add_witness_commitment(block)
        block.solve()
        self.test_cltv_info(is_active=True)
        peer.send_and_ping(msg_block(block))
        self.test_cltv_info(is_active=True)
        assert_equal(self.nodes[0].getbestblockhash(), block.hash)
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.sha256)


if __name__ == '__main__':
    BIP65Test(__file__).main()
