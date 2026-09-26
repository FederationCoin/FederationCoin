#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test behavior of -maxuploadtarget.

* Verify that getdata requests for old blocks (>1week) are dropped
if uploadtarget has been reached.
* Verify that getdata requests for recent blocks are respected even
if uploadtarget has been reached.
* Verify that mempool requests lead to a disconnect if uploadtarget has been reached.
* Verify that the upload counters are reset after 24 hours.
"""
from collections import defaultdict
import time

from test_framework.messages import (
    CInv,
    MSG_BLOCK,
    msg_getdata,
    msg_mempool,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    mine_large_block,
)
from test_framework.wallet import MiniWallet


# Mining phase uses the upstream 800 MiB cap so a full day of reserve (576 MiB)
# still leaves historical serving on. The download phase restarts with a cap
# scaled to this chain's block, so the same ~235 + 800 round trips cross it.
UPLOAD_TARGET_MB = 800
# Knots counted on a ~1MB block. These are those iteration counts.
HISTORICAL_DOWNLOADS = 235
NEW_BLOCK_DOWNLOADS = 800
# OutboundTargetReached reserves (time left / 10 minutes) * this.
MAX_BLOCK_SERIALIZED_SIZE = 4_000_000


class TestP2PConn(P2PInterface):
    def __init__(self):
        super().__init__()
        self.block_receive_map = defaultdict(int)

    def on_inv(self, message):
        pass

    def on_block(self, message):
        message.block.calc_sha256()
        self.block_receive_map[message.block.sha256] += 1

class MaxUploadTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            f"-maxuploadtarget={UPLOAD_TARGET_MB}M",
            "-datacarriersize=100000",
        ]]
        self.supports_cli = False

    def assert_uploadtarget_state(self, *, target_reached, serve_historical_blocks):
        """Verify the node's current upload target state via the `getnettotals` RPC call."""
        uploadtarget = self.nodes[0].getnettotals()["uploadtarget"]
        assert_equal(uploadtarget["target_reached"], target_reached)
        assert_equal(uploadtarget["serve_historical_blocks"], serve_historical_blocks)

    def run_test(self):
        # Initially, neither historical blocks serving limit nor total limit are reached
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=True)

        # Before we connect anything, we first set the time on the node
        # to be in the past, otherwise things break because the CNode
        # time counters can't be reset backward after initialization.
        # Genesis is only days old, so two weeks before wall-clock is before
        # the chain can timestamp a block.
        genesis_time = self.nodes[0].getblockheader(self.nodes[0].getblockhash(0))["time"]
        old_time = max(int(time.time() - 2 * 60 * 60 * 24 * 7), genesis_time + 1)
        self.nodes[0].setmocktime(old_time)

        # Generate some old blocks
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 130)

        # Now mine a big block
        mine_large_block(self, self.wallet, self.nodes[0])

        # Store the hash; we'll request this later
        big_old_block = self.nodes[0].getbestblockhash()
        old_block_size = self.nodes[0].getblock(big_old_block, True)['size']
        big_old_block = int(big_old_block, 16)

        # A block is historical when the tip is more than a week ahead of it.
        # Two days before wall-clock is not a week after genesis.
        # Mined blocks walk forward one second at a time, so the tip must
        # clear a week after the last of those, not after the start time.
        self.nodes[0].setmocktime(old_time + 7 * 24 * 60 * 60 + 2 * 60 * 60)

        # Mine one more block, so that the prior block looks old
        mine_large_block(self, self.wallet, self.nodes[0])

        # We'll be requesting this new block too
        big_new_block = self.nodes[0].getbestblockhash()
        big_new_block = int(big_new_block, 16)

        # p2p_conns[0] will test what happens if we just keep requesting the
        # the same big old block too many times (expect: disconnect)

        new_block_size = self.nodes[0].getblock(self.nodes[0].getbestblockhash())["size"]
        # 800 copies of this block should be enough to cross the total cap, and
        # about 235 copies should be enough to cross the historical reserve.
        # -maxuploadtarget is a whole number of KiB.
        limit = (NEW_BLOCK_DOWNLOADS * new_block_size // 1024) * 1024
        periods = max(1, (limit - HISTORICAL_DOWNLOADS * old_block_size) // MAX_BLOCK_SERIALIZED_SIZE)
        while periods > 1 and periods * MAX_BLOCK_SERIALIZED_SIZE >= limit:
            periods -= 1
        daily_buffer = periods * MAX_BLOCK_SERIALIZED_SIZE
        success_count = (limit - daily_buffer) // old_block_size
        assert success_count > 0
        assert success_count < NEW_BLOCK_DOWNLOADS

        cycle_start = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"] + 1
        self.restart_node(0, extra_args=[
            f"-maxuploadtarget={limit // 1024}K",
            "-datacarriersize=100000",
        ])
        # Start the 24h cycle, then move forward inside it so the reserve
        # shrinks to `periods` of the 4MB block the node still budgets for.
        self.nodes[0].setmocktime(cycle_start)
        probe = self.nodes[0].add_p2p_connection(TestP2PConn(), supports_v2_p2p=False)
        probe.sync_with_ping()
        self.nodes[0].setmocktime(cycle_start + 24 * 60 * 60 - periods * 10 * 60)
        self.nodes[0].disconnect_p2ps()

        # p2p_conns[0] requests old blocks, [1] requests the new block,
        # [2] checks that the counters reset. v2 transport is left off:
        # the Python ChaCha20 implementation is too slow for this many round trips.
        p2p_conns = []
        for _ in range(3):
            p2p_conns.append(self.nodes[0].add_p2p_connection(TestP2PConn(), supports_v2_p2p=False))
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=True)

        getdata_request = msg_getdata()
        getdata_request.inv.append(CInv(MSG_BLOCK, big_old_block))

        # The reserve is a few hours of the 4MB budget, not a full day, so this
        # is about 235 transfers of the reduced-data block.
        for i in range(success_count):
            p2p_conns[0].send_and_ping(getdata_request)
            assert_equal(p2p_conns[0].block_receive_map[big_old_block], i+1)

        assert_equal(len(self.nodes[0].getpeerinfo()), 3)
        # At most a couple more tries should succeed (depending on how long
        # the test has been running so far).
        with self.nodes[0].assert_debug_log(expected_msgs=["historical block serving limit reached, disconnecting peer="]):
            for _ in range(3):
                p2p_conns[0].send_message(getdata_request)
            p2p_conns[0].wait_for_disconnect()
        assert_equal(len(self.nodes[0].getpeerinfo()), 2)
        self.log.info("Peer 0 disconnected after downloading old block too many times")

        # Historical blocks serving limit is reached by now, but total limit still isn't
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=False)

        # Requesting the current block on p2p_conns[1] should succeed
        # even when over the max upload target. 800 copies of this block
        # cross the cap set at restart.
        getdata_request.inv = [CInv(MSG_BLOCK, big_new_block)]
        for i in range(NEW_BLOCK_DOWNLOADS):
            p2p_conns[1].send_and_ping(getdata_request)
            assert_equal(p2p_conns[1].block_receive_map[big_new_block], i+1)

        # Both historical blocks serving limit and total limit are reached
        self.assert_uploadtarget_state(target_reached=True, serve_historical_blocks=False)

        self.log.info("Peer 1 able to repeatedly download new block")

        # But if p2p_conns[1] tries for an old block, it gets disconnected too.
        getdata_request.inv = [CInv(MSG_BLOCK, big_old_block)]
        with self.nodes[0].assert_debug_log(expected_msgs=["historical block serving limit reached, disconnecting peer="]):
            p2p_conns[1].send_message(getdata_request)
            p2p_conns[1].wait_for_disconnect()
        assert_equal(len(self.nodes[0].getpeerinfo()), 1)

        self.log.info("Peer 1 disconnected after trying to download old block")

        self.log.info("Advancing system time on node to clear counters...")

        # Advancing a full day clears the byte counter. A full day also
        # reserves 576MB, which is more than this block-sized cap, so
        # historical serving stays off until the window shrinks again.
        # Land on the same reserve the download phase used.
        reset_start = cycle_start + 24 * 60 * 60 + 1
        self.nodes[0].setmocktime(reset_start)
        p2p_conns[2].sync_with_ping()
        self.nodes[0].setmocktime(reset_start + 24 * 60 * 60 - periods * 10 * 60)
        p2p_conns[2].sync_with_ping()
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=True)
        p2p_conns[2].send_and_ping(getdata_request)
        assert_equal(p2p_conns[2].block_receive_map[big_old_block], 1)
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=True)

        self.log.info("Peer 2 able to download old block")

        self.nodes[0].disconnect_p2ps()

        self.log.info("Restarting node 0 with download permission, bloom filter support and 1MB maxuploadtarget")
        self.restart_node(0, ["-whitelist=download@127.0.0.1", "-peerbloomfilters", "-maxuploadtarget=1"])
        # Total limit isn't reached after restart, but 1 MB is too small to serve historical blocks
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=False)

        # Reconnect to self.nodes[0]
        peer = self.nodes[0].add_p2p_connection(TestP2PConn(), supports_v2_p2p=False)

        # Sending mempool message shouldn't disconnect peer, as total limit isn't reached yet
        peer.send_and_ping(msg_mempool())

        #retrieve 20 blocks which should be enough to break the 1MB limit
        getdata_request.inv = [CInv(MSG_BLOCK, big_new_block)]
        for i in range(20):
            peer.send_and_ping(getdata_request)
            assert_equal(peer.block_receive_map[big_new_block], i+1)

        # Total limit is exceeded
        self.assert_uploadtarget_state(target_reached=True, serve_historical_blocks=False)

        getdata_request.inv = [CInv(MSG_BLOCK, big_old_block)]
        peer.send_and_ping(getdata_request)

        self.log.info("Peer still connected after trying to download old block (download permission)")
        peer_info = self.nodes[0].getpeerinfo()
        assert_equal(len(peer_info), 1)  # node is still connected
        assert_equal(peer_info[0]['permissions'], ['download'])

        self.log.info("Peer gets disconnected for a mempool request after limit is reached")
        with self.nodes[0].assert_debug_log(expected_msgs=["mempool request with bandwidth limit reached, disconnecting peer=0"]):
            peer.send_message(msg_mempool())
            peer.wait_for_disconnect()

        self.log.info("Test passing an unparsable value to -maxuploadtarget throws an error")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(extra_args=["-maxuploadtarget=abc"], expected_msg="Error: Unable to parse -maxuploadtarget: 'abc'")

if __name__ == '__main__':
    MaxUploadTest(__file__).main()
