#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the pruning code.

WARNING:
This test uses 4GB of disk space.
"""
import os

from test_framework.blocktools import (
    MIN_BLOCKS_TO_KEEP,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    CTxOut,
    REDUCED_DATA_MAX_BLOCK_WEIGHT,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    try_rpc,
)

# Rescans start at the earliest block up to 2 hours before a key timestamp, so
# the manual prune RPC avoids pruning blocks in the same window to be
# compatible with pruning based on key creation time.
TIMESTAMP_WINDOW = 2 * 60 * 60

# A block file chunk. Pruning runs when the next chunk is allocated.
BLOCKFILE_CHUNK = 16 * 1024 * 1024
# Auto-prune target the test has to exceed.
PRUNE_BYTES = 550 * 1024 * 1024

def _rdts_pad_outputs():
    """Zero-value OP_RETURN outputs that fill a coinbase up to the RDTS weight cap.

    A 950KB coinbase script is over the 83-byte OP_RETURN cap. Build the
    output list once; every large block in this test reuses it.
    """
    cached = getattr(_rdts_pad_outputs, "vout", None)
    if cached is not None:
        return cached
    pad = CScript([OP_RETURN, b"x" * 80])
    one = CTxOut(0, pad)
    lo, hi = 0, 4000
    best = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        coinbase = create_coinbase(1)
        coinbase.vout.extend([one] * mid)
        coinbase.sha256 = None
        coinbase.calc_sha256()
        block = create_block(1, coinbase, ntime=1, height=1)
        if block.get_weight() <= REDUCED_DATA_MAX_BLOCK_WEIGHT:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    _rdts_pad_outputs.vout = [one] * best
    sample = create_block(1, create_coinbase(1), ntime=1, height=1)
    sample.vtx[0].vout.extend(_rdts_pad_outputs.vout)
    sample.vtx[0].calc_sha256()
    sample.hashMerkleRoot = sample.calc_merkle_root()
    _rdts_pad_outputs.size = len(sample.serialize())
    return _rdts_pad_outputs.vout

def blocks_for(num_bytes):
    _rdts_pad_outputs()
    return num_bytes // _rdts_pad_outputs.size + 1

def mine_large_blocks(node, n):
    # Set the nTime if this is the first time this function has been called.
    # A static variable ensures that time is monotonicly increasing and is therefore
    # different for each block created => blockhash is unique.
    if "nTime" not in mine_large_blocks.__dict__:
        mine_large_blocks.nTime = 0

    pad = _rdts_pad_outputs()
    best_block = node.getblock(node.getbestblockhash())
    height = int(best_block["height"]) + 1
    mine_large_blocks.nTime = max(mine_large_blocks.nTime, int(best_block["time"])) + 1
    previousblockhash = int(best_block["hash"], 16)

    for _ in range(n):
        coinbase = create_coinbase(height)
        coinbase.vout.extend(pad)
        coinbase.sha256 = None
        coinbase.calc_sha256()
        block = create_block(hashprev=previousblockhash, ntime=mine_large_blocks.nTime, coinbase=coinbase, height=height)
        block.solve()

        result = node.submitblock(block.serialize().hex())
        assert result is None, result

        previousblockhash = block.sha256
        height += 1
        mine_large_blocks.nTime += 1

def calc_usage(blockdir):
    return sum(os.path.getsize(blockdir + f) for f in os.listdir(blockdir) if os.path.isfile(os.path.join(blockdir, f))) / (1024. * 1024.)

class PruneTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 6
        self.supports_cli = False

        # Create nodes 0 and 1 to mine.
        # Create node 2 to test pruning.
        self.full_node_default_args = ["-maxreceivebuffer=20000", "-checkblocks=5"]
        # Create nodes 3 and 4 to test manual pruning (they will be re-started with manual pruning later)
        # Create nodes 5 to test wallet in prune mode, but do not connect
        self.extra_args = [
            self.full_node_default_args,
            self.full_node_default_args,
            ["-maxreceivebuffer=20000", "-prune=550"],
            ["-maxreceivebuffer=20000"],
            ["-maxreceivebuffer=20000"],
            ["-prune=550", "-blockfilterindex=1"],
        ]
        self.rpc_timeout = 120

    def setup_network(self):
        self.setup_nodes()

        self.prunedir = os.path.join(self.nodes[2].blocks_path, '')

        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(0, 2)
        self.connect_nodes(0, 3)
        self.connect_nodes(0, 4)
        self.sync_blocks(self.nodes[0:5])

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()
        if self.is_wallet_compiled():
            self.import_deterministic_coinbase_privkeys()

    def create_big_chain(self):
        # Start by creating some coinbases we can spend later
        self.generate(self.nodes[1], 200, sync_fun=lambda: self.sync_blocks(self.nodes[0:2]))
        self.generate(self.nodes[0], 150, sync_fun=self.no_op)
        self.sync_blocks(self.nodes[0:5])
        # PruneAfterHeight is 1000. This prefix is still below it.
        assert self.nodes[3].getblockcount() < 1000
        self.restart_node(3, extra_args=["-prune=1"])
        assert_raises_rpc_error(-1, "Blockchain is too short for pruning", self.nodes[3].pruneblockchain, 500)
        self.restart_node(3)
        self.connect_nodes(0, 3)

        # Then mine enough RDTS-capped blocks to create more than 550MiB of data.
        # A 950KB coinbase no longer fits, so this is more blocks than 645.
        mine_large_blocks(self.nodes[0], blocks_for(PRUNE_BYTES))

        self.sync_blocks(self.nodes[0:5])
        self.chain_height = self.nodes[0].getblockcount()

    def test_invalid_command_line_options(self):
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Prune cannot be configured with a negative value.',
            extra_args=['-prune=-1'],
        )
        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Prune configured below the minimum of 550 MiB.  Please use a higher number.',
            extra_args=['-prune=549'],
        )
        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Prune mode is incompatible with -txindex.',
            extra_args=['-prune=550', '-txindex'],
        )
        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Prune mode is incompatible with -reindex-chainstate. Use full -reindex instead.',
            extra_args=['-prune=550', '-reindex-chainstate'],
        )

    def test_rescan_blockchain(self):
        self.restart_node(0, ["-prune=550"])
        assert_raises_rpc_error(-1, "Can't rescan beyond pruned data. Use RPC call getblockchaininfo to determine your pruned height.", self.nodes[0].rescanblockchain)

    def test_height_min(self):
        # Filling 550 MiB of RDTS-capped blocks passes PruneAfterHeight (1000),
        # so the first file may already be gone. If it is still there, one
        # more chunk allocation is what makes pruning run.
        first_file = os.path.join(self.prunedir, "blk00000.dat")
        self.log.info(f"Prune dir usage before forcing a chunk: {calc_usage(self.prunedir)}")
        if os.path.isfile(first_file):
            mine_large_blocks(self.nodes[0], blocks_for(BLOCKFILE_CHUNK))
            self.sync_blocks(self.nodes[0:3])
            self.wait_until(lambda: not os.path.isfile(first_file), timeout=30)

        usage = calc_usage(self.prunedir)
        self.log.info(f"Usage should be below target: {usage}")
        assert_greater_than(550, usage)

    def create_chain_with_staleblocks(self):
        # Create stale blocks in manageable sized chunks
        self.log.info("Mine 24 (stale) blocks on Node 1, followed by 25 (main chain) block reorg from Node 0, for 12 rounds")

        for _ in range(12):
            # Disconnect node 0 so it can mine a longer reorg chain without knowing about node 1's soon-to-be-stale chain
            # Node 2 stays connected, so it hears about the stale blocks and then reorg's when node0 reconnects
            self.disconnect_nodes(0, 1)
            self.disconnect_nodes(0, 2)
            # Mine 24 blocks in node 1
            mine_large_blocks(self.nodes[1], 24)

            # Reorg back with 25 block chain from node 0
            mine_large_blocks(self.nodes[0], 25)

            # Create connections in the order so both nodes can see the reorg at the same time
            self.connect_nodes(0, 1)
            self.connect_nodes(0, 2)
            self.sync_blocks(self.nodes[0:3])

        self.log.info(f"Usage can be over target because of high stale rate: {calc_usage(self.prunedir)}")

    def reorg_test(self):
        # Node 1 will mine a 300 block chain starting 287 blocks back from Node 0 and Node 2's tip
        # This will cause Node 2 to do a reorg requiring 288 blocks of undo data to the reorg_test chain

        height = self.nodes[1].getblockcount()
        self.log.info(f"Current block height: {height}")

        self.forkheight = height - 287
        self.forkhash = self.nodes[1].getblockhash(self.forkheight)
        self.log.info(f"Invalidating block {self.forkhash} at height {self.forkheight}")
        self.nodes[1].invalidateblock(self.forkhash)

        # We've now switched to our previously mined-24 block fork on node 1, but that's not what we want
        # So invalidate that fork as well, until we're on the same chain as node 0/2 (but at an ancestor 288 blocks ago)
        mainchainhash = self.nodes[0].getblockhash(self.forkheight - 1)
        curhash = self.nodes[1].getblockhash(self.forkheight - 1)
        while curhash != mainchainhash:
            self.nodes[1].invalidateblock(curhash)
            curhash = self.nodes[1].getblockhash(self.forkheight - 1)

        assert self.nodes[1].getblockcount() == self.forkheight - 1
        self.log.info(f"New best height: {self.nodes[1].getblockcount()}")

        # Disconnect node1 and generate the new chain
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)

        self.log.info("Generating new longer chain of 300 more blocks")
        self.generate(self.nodes[1], 300, sync_fun=self.no_op)

        self.log.info("Reconnect nodes")
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.sync_blocks(self.nodes[0:3], timeout=120)

        self.log.info(f"Verify height on node 2: {self.nodes[2].getblockcount()}")
        self.log.info(f"Usage possibly still high because of stale blocks in block files: {calc_usage(self.prunedir)}")

        self.log.info("Mine 220 more blocks so the reorg has history after the fork")
        # Block count, not bytes: 220 is inside the story of the reorg test.
        # It does not try to refill 550 MiB. RDTS blocks are smaller, so this
        # does not by itself evict the fork from the prune window.
        mine_large_blocks(self.nodes[0], 220)
        self.sync_blocks(self.nodes[0:3], timeout=120)

        usage = calc_usage(self.prunedir)
        self.log.info(f"Usage should be below target: {usage}")
        assert_greater_than(550, usage)

    def reorg_back(self):
        # A 550 MiB window holds more RDTS blocks than it held ~1MB blocks, so
        # the fork is often still on disk. Ask prune to drop it. If the file
        # still contains kept blocks, the fork stays, and there is nothing to
        # re-request. Do not mine another 550 MiB just to evict it.
        self.nodes[2].pruneblockchain(self.forkheight + 1)
        if not try_rpc(-1, "Block not available (pruned data)", self.nodes[2].getblock, self.forkhash):
            self.log.info("Fork block still fits in the 550 MiB window; skipping the re-request")
            return
        # Verify that a block on the old main chain fork has been pruned away
        assert_raises_rpc_error(-1, "Block not available (pruned data)", self.nodes[2].getblock, self.forkhash)
        with self.nodes[2].assert_debug_log(expected_msgs=['block verification stopping at height', '(no data)']):
            assert not self.nodes[2].verifychain(checklevel=4, nblocks=0)
        self.log.info(f"Will need to redownload block {self.forkheight}")

        # Verify that we have enough history to reorg back to the fork point
        # Although this is more than 288 blocks, because this chain was written more recently
        # and only its other 299 small and 220 large blocks are in the block files after it,
        # it is expected to still be retained
        self.nodes[2].getblock(self.nodes[2].getblockhash(self.forkheight))

        first_reorg_height = self.nodes[2].getblockcount()
        # One 25-block segment before the tip. Was height 1295 when the
        # prefix was 995 blocks of ~1MB.
        block_hash_recent = self.nodes[2].getblockhash(self.mainchainheight - 25)
        self.nodes[2].invalidateblock(block_hash_recent)
        goalbestheight = self.mainchainheight
        goalbesthash = self.mainchainhash2

        # As of 0.10 the current block download logic is not able to reorg to the original chain created in
        # create_chain_with_stale_blocks because it doesn't know of any peer that's on that chain from which to
        # redownload its missing blocks.
        # Invalidate the reorg_test chain in node 0 as well, it can successfully switch to the original chain
        # because it has all the block data.
        # However it must mine enough blocks to have a more work chain than the reorg_test chain in order
        # to trigger node 2's block download logic.
        # At this point node 2 is within 288 blocks of the fork point so it will preserve its ability to reorg
        if self.nodes[2].getblockcount() < self.mainchainheight:
            blocks_to_mine = first_reorg_height + 1 - self.mainchainheight
            self.log.info(f"Rewind node 0 to prev main chain to mine longer chain to trigger redownload. Blocks needed: {blocks_to_mine}")
            self.nodes[0].invalidateblock(block_hash_recent)
            assert_equal(self.nodes[0].getblockcount(), self.mainchainheight)
            assert_equal(self.nodes[0].getbestblockhash(), self.mainchainhash2)
            goalbesthash = self.generate(self.nodes[0], blocks_to_mine, sync_fun=self.no_op)[-1]
            goalbestheight = first_reorg_height + 1

        self.log.info("Verify node 2 reorged back to the main chain, some blocks of which it had to redownload")
        # Wait for Node 2 to reorg to proper height
        self.wait_until(lambda: self.nodes[2].getblockcount() >= goalbestheight, timeout=900)
        assert_equal(self.nodes[2].getbestblockhash(), goalbesthash)
        # Verify we can now have the data for a block previously pruned
        assert_equal(self.nodes[2].getblock(self.forkhash)["height"], self.forkheight)

    def manual_test(self, node_number, use_timestamp):
        # at this point, node has 995 blocks and has not yet run in prune mode
        self.start_node(node_number)
        node = self.nodes[node_number]
        assert_equal(node.getblockcount(), self.chain_height)
        assert_raises_rpc_error(-1, "Cannot prune blocks because node is not in prune mode", node.pruneblockchain, 500)

        # now re-start in manual pruning mode
        self.restart_node(node_number, extra_args=["-prune=1"])
        node = self.nodes[node_number]
        assert_equal(node.getblockcount(), self.chain_height)

        def height(index):
            if use_timestamp:
                return node.getblockheader(node.getblockhash(index))["time"] + TIMESTAMP_WINDOW
            else:
                return index

        def prune(index):
            ret = node.pruneblockchain(height=height(index))
            assert_equal(ret + 1, node.getblockchaininfo()['pruneheight'])

        def has_block(index):
            return os.path.isfile(os.path.join(self.nodes[node_number].blocks_path, f"blk{index:05}.dat"))

        # PruneAfterHeight is 1000. The filled chain is past that, so this
        # rejection only applies when the tip is still below it.
        if node.getblockcount() < 1000:
            assert_raises_rpc_error(-1, "Blockchain is too short for pruning", node.pruneblockchain, height(500))

        # Save block transaction count before pruning, assert value
        block1_details = node.getblock(node.getblockhash(1))
        assert_equal(block1_details["nTx"], len(block1_details["tx"]))

        # Get above PruneAfterHeight (1000). The filled chain may already be there.
        if node.getblockcount() < 1001:
            self.generate(node, 1001 - node.getblockcount(), sync_fun=self.no_op)
        assert node.getblockchaininfo()["blocks"] >= 1001

        # prune parameter in the future (block or timestamp) should raise an exception
        future_parameter = height(node.getblockcount()) + 5
        if use_timestamp:
            assert_raises_rpc_error(-8, "Could not find block with at least the specified timestamp", node.pruneblockchain, future_parameter)
        else:
            assert_raises_rpc_error(-8, "Blockchain is shorter than the attempted prune height", node.pruneblockchain, future_parameter)

        # Pruned block should still know the number of transactions
        assert_equal(node.getblockheader(node.getblockhash(1))["nTx"], block1_details["nTx"])

        # negative heights should raise an exception
        assert_raises_rpc_error(-8, "Negative block height", node.pruneblockchain, -10)

        # height=100 too low to prune first block file so this is a no-op
        prune(100)
        assert has_block(0), "blk00000.dat is missing when should still be there"

        # Does nothing
        node.pruneblockchain(height(0))
        assert has_block(0), "blk00000.dat is missing when should still be there"

        # The short prefix of ordinary blocks sits at the front of file 0.
        # File i then ends near prefix + (i+1) files of RDTS blocks.
        blocks_per_file = max(1, (128 * 1024 * 1024) // _rdts_pad_outputs.size)
        prefix = self.chain_height - blocks_for(PRUNE_BYTES)

        def file_end(index):
            return prefix + (index + 1) * blocks_per_file

        # A prune lock keeps the first file even past its end.
        node.setprunelock("test", {
            "desc": "Testing",
            "height": [2, 2],
        })
        assert_equal(node.listprunelocks(), {'prune_locks': [{'id': 'test', 'desc': 'Testing', 'height': [2, 2], 'temporary': False}]})
        prune(file_end(0) + 1)
        assert has_block(0), "blk00000.dat is missing when should still be there"
        node.setprunelock("test", {})  # delete prune lock
        assert_equal(node.listprunelocks(), {'prune_locks': []})

        # Past the first file: file 0 goes, file 1 stays.
        prune(file_end(0) + 1)
        assert not has_block(0), "blk00000.dat is still there, should be pruned by now"
        assert has_block(1), "blk00001.dat is missing when should still be there"

        # Past the second file.
        prune(file_end(1) + 1)
        assert not has_block(1), "blk00001.dat is still there, should be pruned by now"
        assert has_block(2), "blk00002.dat is missing when should still be there"

        # Move the tip so files 2 and 3 are below the keep window, then prune them.
        self.generate(node, blocks_per_file + MIN_BLOCKS_TO_KEEP, sync_fun=self.no_op)
        prune(file_end(3) + 1)
        assert not has_block(2), "blk00002.dat is still there, should be pruned by now"
        assert not has_block(3), "blk00003.dat is still there, should be pruned by now"

        # stop node, start back up with auto-prune at 550 MiB, make sure still runs
        self.restart_node(node_number, extra_args=["-prune=550"])

        self.log.info("Success")

    def test_wallet_rescan(self):
        # check that the pruning node's wallet is still in good shape
        self.log.info("Stop and start pruning node to trigger wallet rescan")
        self.restart_node(2, extra_args=["-prune=550"])

        self.wait_until(lambda: self.nodes[2].getwalletinfo()["scanning"] == False)
        self.wait_until(lambda: self.nodes[2].getwalletinfo()["lastprocessedblock"]["height"] == self.nodes[2].getblockcount())

        # check that wallet loads successfully when restarting a pruned node after IBD.
        # this was reported to fail in #7494.
        self.restart_node(5, extra_args=["-prune=550", "-blockfilterindex=1"]) # restart to trigger rescan

        self.wait_until(lambda: self.nodes[5].getwalletinfo()["scanning"] == False)
        self.wait_until(lambda: self.nodes[5].getwalletinfo()["lastprocessedblock"]["height"] == self.nodes[0].getblockcount())

    def run_test(self):
        self.log.info("Warning! This test requires 4GB of disk space")

        self.log.info("Mining a big blockchain of 995 blocks")
        self.create_big_chain()
        # Chain diagram key:
        # *   blocks on main chain
        # +,&,$,@ blocks on other forks
        # X   invalidated block
        # N1  Node 1
        #
        # Start by mining a simple chain that all nodes have
        # N0=N1=N2 **...*(995)

        # stop manual-pruning node with 995 blocks
        self.stop_node(3)
        self.stop_node(4)

        self.log.info("Check that auto-prune holds the chain under 550 MiB once the tip is past PruneAfterHeight")
        self.test_height_min()
        # Extend this chain past the PruneAfterHeight
        # N0=N1=N2 **...*(1020)

        self.log.info("Check that we'll exceed disk space target if we have a very high stale block rate")
        self.create_chain_with_staleblocks()
        # Disconnect N0
        # And mine a 24 block chain on N1 and a separate 25 block chain on N0
        # N1=N2 **...*+...+(1044)
        # N0    **...**...**(1045)
        #
        # reconnect nodes causing reorg on N1 and N2
        # N1=N2 **...*(1020) *...**(1045)
        #                   \
        #                    +...+(1044)
        #
        # repeat this process until you have 12 stale forks hanging off the
        # main chain on N1 and N2
        # N0    *************************...***************************(1320)
        #
        # N1=N2 **...*(1020) *...**(1045) *..         ..**(1295) *...**(1320)
        #                   \            \                      \
        #                    +...+(1044)  &..                    $...$(1319)

        # Save some current chain state for later use
        self.mainchainheight = self.nodes[2].getblockcount()  # 1320
        self.mainchainhash2 = self.nodes[2].getblockhash(self.mainchainheight)

        self.log.info("Check that we can survive a 288 block reorg still")
        self.reorg_test()  # (1033, )
        # Now create a 288 block reorg by mining a longer chain on N1
        # First disconnect N1
        # Then invalidate 1033 on main chain and 1032 on fork so height is 1032 on main chain
        # N1   **...*(1020) **...**(1032)X..
        #                  \
        #                   ++...+(1031)X..
        #
        # Now mine 300 more blocks on N1
        # N1    **...*(1020) **...**(1032) @@...@(1332)
        #                 \               \
        #                  \               X...
        #                   \                 \
        #                    ++...+(1031)X..   ..
        #
        # Reconnect nodes and mine 220 more blocks on N1
        # N1    **...*(1020) **...**(1032) @@...@@@(1552)
        #                 \               \
        #                  \               X...
        #                   \                 \
        #                    ++...+(1031)X..   ..
        #
        # N2    **...*(1020) **...**(1032) @@...@@@(1552)
        #                 \               \
        #                  \               *...**(1320)
        #                   \                 \
        #                    ++...++(1044)     ..
        #
        # N0    ********************(1032) @@...@@@(1552)
        #                                 \
        #                                  *...**(1320)

        self.log.info("Test that we can rerequest a block we previously pruned if needed for a reorg")
        self.reorg_back()
        # Verify that N2 still has block 1033 on current chain (@), but not on main chain (*)
        # Invalidate 1033 on current chain (@) on N2 and we should be able to reorg to
        # original main chain (*), but will require redownload of some blocks
        # In order to have a peer we think we can download from, must also perform this invalidation
        # on N0 and mine a new longest chain to trigger.
        # Final result:
        # N0    ********************(1032) **...****(1553)
        #                                 \
        #                                  X@...@@@(1552)
        #
        # N2    **...*(1020) **...**(1032) **...****(1553)
        #                 \               \
        #                  \               X@...@@@(1552)
        #                   \
        #                    +..
        #
        # N1 doesn't change because 1033 on main chain (*) is invalid

        self.log.info("Test manual pruning with block indices")
        self.manual_test(3, use_timestamp=False)

        self.log.info("Test manual pruning with timestamps")
        self.manual_test(4, use_timestamp=True)

        self.log.info("Syncing node 5 to node 0")
        self.connect_nodes(0, 5)
        self.sync_blocks([self.nodes[0], self.nodes[5]], wait=5, timeout=300)

        if self.is_wallet_compiled():
            self.log.info("Test wallet re-scan")
            self.test_wallet_rescan()

            self.log.info("Test it's not possible to rescan beyond pruned data")
            self.test_rescan_blockchain()

        self.log.info("Test invalid pruning command line options")
        self.test_invalid_command_line_options()

        self.log.info("Test scanblocks can not return pruned data")
        self.test_scanblocks_pruned()

        self.log.info("Test pruneheight reflects the presence of block and undo data")
        self.test_pruneheight_undo_presence()

        self.log.info("Done")

    def test_scanblocks_pruned(self):
        node = self.nodes[5]
        genesis_blockhash = node.getblockhash(0)
        false_positive_spk = bytes.fromhex("001400000000000000000000000000000000000cadcb")

        # This script collides with Bitcoin's genesis block filter. This
        # chain's genesis is different, so the collision is not required.
        unfiltered = node.scanblocks(
            "start", [{"desc": f"raw({false_positive_spk.hex()})"}], 0, 0)['relevant_blocks']
        if genesis_blockhash not in unfiltered:
            self.log.info("Genesis filter does not false-positive on this chain; skipping the pruned read")
            return
        assert_raises_rpc_error(-1, "Block not available (pruned data)", node.scanblocks,
            "start", [{"desc": f"raw({false_positive_spk.hex()})"}], 0, 0, "basic", {"filter_false_positives": True})

    def test_pruneheight_undo_presence(self):
        node = self.nodes[5]
        pruneheight = node.getblockchaininfo()["pruneheight"]
        fetch_block = node.getblockhash(pruneheight - 1)

        self.connect_nodes(1, 5)
        peers = node.getpeerinfo()
        node.getblockfrompeer(fetch_block, peers[0]["id"])
        self.wait_until(lambda: not try_rpc(-1, "Block not available (pruned data)", node.getblock, fetch_block), timeout=5)

        new_pruneheight = node.getblockchaininfo()["pruneheight"]
        assert_equal(pruneheight, new_pruneheight)

if __name__ == '__main__':
    PruneTest(__file__).main()
