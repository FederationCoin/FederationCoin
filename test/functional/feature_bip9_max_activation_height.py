#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test max_activation_height for mandatory BIP9 activation.

This test verifies that BIP9 deployments with max_activation_height properly
activate at the specified height regardless of miner signaling, similar to BIP8.

The test verifies four critical scenarios:
1. Mandatory activation at max_height without signaling
2. Normal deployment without max_height (requires signaling)
3. Early activation via signaling before reaching max_height
4. Max_height overrides timeout

Expected behavior:
- When max_activation_height is set and reached while in STARTED state,
  the deployment transitions to LOCKED_IN (then ACTIVE) regardless of signaling
- Max_activation_height overrides timeout
- Once ACTIVE, the deployment remains ACTIVE permanently (terminal state)
- Without max_activation_height, activation requires sufficient signaling
"""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    add_witness_commitment,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

TESTDUMMY_BIT = 28
VERSIONBITS_TOP_BITS = 0x20000000


class MaxActivationHeightTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 6  # 6 nodes for tests 1-6 (test 0 validation is done separately)
        self.setup_clean_chain = True
        # NO_TIMEOUT = std::numeric_limits<int64_t>::max() = 9223372036854775807
        NO_TIMEOUT = '9223372036854775807'
        # INT_MAX = std::numeric_limits<int>::max() = 2147483647
        INT_MAX = '2147483647'
        self.extra_args = [
            [f'-vbparams=testdummy:0:{NO_TIMEOUT}:0:480:120'],      # Test 1: max_height=480 (4 * 120)
            ['-vbparams=testdummy:0:999999999999'],                 # Test 2: no max_height (uses timeout)
            [f'-vbparams=testdummy:0:{NO_TIMEOUT}:0:480:120'],      # Test 3: max_height=480
            [f'-vbparams=testdummy:0:{NO_TIMEOUT}:0:360:{INT_MAX}'], # Test 4: verify permanent ACTIVE
            [f'-vbparams=testdummy:0:{NO_TIMEOUT}:0:360:120'],      # Test 5: max_height + active_duration
            [f'-vbparams=testdummy:0:999999999999:0:{INT_MAX}:{INT_MAX}:60'],  # Test 6: 50% threshold (60/120)
        ]

    def setup_network(self):
        """Keep nodes isolated - don't connect them to each other"""
        self.add_nodes(self.num_nodes)
        for i in range(self.num_nodes):
            self.start_node(i, extra_args=self.extra_args[i])
        # Nodes remain disconnected for independent blockchain testing

    def mine_blocks(self, node, count, signal=False):
        """Mine count blocks, optionally signaling for testdummy."""
        for i in range(count):
            tip = node.getbestblockhash()
            height = node.getblockcount() + 1
            tip_header = node.getblockheader(tip)
            block_time = tip_header['time'] + 1
            block = create_block(int(tip, 16), create_coinbase(height), ntime=block_time, height=height)
            if signal:
                block.nVersion = VERSIONBITS_TOP_BITS | (1 << TESTDUMMY_BIT)
            add_witness_commitment(block)
            block.solve()
            node.submitblock(block.serialize().hex())

            # Log every 20 blocks and at key heights for debugging
            if height % 20 == 0 or height == 119 or height == 120:
                mtp = node.getblockheader(node.getbestblockhash())['mediantime']
                self.log.info(f"  Block {height}: time={block_time}, MTP={mtp}")

    def get_status(self, node):
        """Get testdummy deployment status."""
        info = node.getdeploymentinfo()
        td = info['deployments']['testdummy']
        if 'bip9' in td:
            return td['bip9']['status'], td['bip9'].get('since', 0)
        return td.get('status', 'unknown'), 0

    def run_test(self):
        # Test 0: Verify validation rejects both timeout and max_activation_height
        self.log.info("=== TEST 0: Validation test - reject both timeout and max_activation_height ===")
        self.log.info("Attempting to start bitcoind with both timeout and max_activation_height...")

        # Run bitcoind directly with invalid config to test validation
        import subprocess
        import os

        # Get the bitcoind binary path from the test framework
        bitcoind_path = self.options.bitcoind

        # Create a temporary datadir for this test
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                # Run bitcoind with invalid vbparams (both timeout and max_activation_height)
                result = subprocess.run(
                    [bitcoind_path, f'-datadir={tmpdir}', '-regtest',
                     '-vbparams=testdummy:0:1:0:360'],  # timeout=1, max_activation_height=360
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                # If we get here with exit code 0, the validation failed
                if result.returncode == 0:
                    raise AssertionError("bitcoind should have failed to start with both timeout and max_activation_height")

                # Check that the error message contains the expected validation error
                error_output = result.stderr
                self.log.info(f"bitcoind correctly failed with error: {error_output[:200]}")

                assert "Cannot specify both timeout" in error_output and "max_activation_height" in error_output, \
                    f"Expected validation error about both parameters, got: {error_output}"

                self.log.info("SUCCESS: Validation correctly rejected invalid configuration")

            except subprocess.TimeoutExpired:
                raise AssertionError("bitcoind timed out (should have failed immediately with validation error)")

        self.log.info("\n=== Test: max_activation_height=480 (full flow with non-mandatory period) ===")
        node = self.nodes[0]

        # Check deployment info to verify max_activation_height is set
        info = node.getdeploymentinfo()
        self.log.info(f"Deployment info: {info['deployments']['testdummy']}")

        # Period 0 (0-119): DEFINED
        self.log.info("\n--- Period 0 (blocks 0-119): DEFINED ---")
        self.mine_blocks(node, 119, signal=False)
        assert_equal(node.getblockcount(), 119)
        status, since = self.get_status(node)
        self.log.info(f"Block 119: Status={status}")
        assert_equal(status, 'defined')

        # Block 120: Transition to STARTED
        self.log.info("\n--- Block 120: Transition to STARTED ---")
        self.mine_blocks(node, 1, signal=False)
        status, since = self.get_status(node)
        self.log.info(f"Block 120: Status={status}, Since={since}")
        assert_equal(status, 'started')
        assert_equal(since, 120)

        # Period 1 (120-239): STARTED
        self.log.info("\n--- Period 1 (blocks 145-239): STARTED ---")
        self.mine_blocks(node, 119, signal=False)
        assert_equal(node.getblockcount(), 239)
        status, since = self.get_status(node)
        self.log.info(f"Block 239: Status={status}")
        assert_equal(status, 'started')

        # Period 2 (240-359): STARTED - forced lock-in will occur at end of this period
        self.log.info("\n--- Period 2 (blocks 240-359): STARTED ---")
        self.log.info("Forced lock-in will occur at block 360 (max_activation_height - nPeriod)")

        # Try to mine block 240 without signaling - should be REJECTED
        self.log.info("\nNEGATIVE TEST: Attempting to mine block 240 without signaling...")
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        tip_header = node.getblockheader(tip)
        block_time = tip_header['time'] + 1
        block = create_block(int(tip, 16), create_coinbase(height), ntime=block_time, height=height)
        block.nVersion = VERSIONBITS_TOP_BITS  # No signaling bit
        add_witness_commitment(block)
        block.solve()
        result = node.submitblock(block.serialize().hex())
        self.log.info(f"Submitblock result (should be rejected): {result}")
        # Block should be rejected - check we're still at block 239
        assert_equal(node.getblockcount(), 239)
        self.log.info("SUCCESS: Block without signaling was correctly REJECTED during enforcement window")

        # Now mine Period 2 with proper signaling
        self.log.info("\nMining Period 2 with proper signaling...")
        self.mine_blocks(node, 120, signal=True)
        assert_equal(node.getblockcount(), 359)
        status, since = self.get_status(node)
        self.log.info(f"Block 359: Status={status}")
        assert_equal(status, 'started')

        # Period 3 (360-479): LOCKED_IN (forced by max_activation_height)
        self.log.info("\n--- Period 3 (blocks 360-479): LOCKED_IN ---")
        self.mine_blocks(node, 1, signal=False)  # Mine block 360
        assert_equal(node.getblockcount(), 360)
        status, since = self.get_status(node)
        self.log.info(f"Block 360: Status={status}, Since={since}")
        assert_equal(status, 'locked_in')
        assert_equal(since, 360)

        # Mine through period 3 to activate at block 480
        self.log.info("Mining blocks 433-479...")
        self.mine_blocks(node, 119, signal=False)
        assert_equal(node.getblockcount(), 479)
        status, since = self.get_status(node)
        assert_equal(status, 'locked_in')

        # Period 4 (480+): ACTIVE
        self.log.info("\n--- Period 4 (block 480+): ACTIVE ---")
        self.mine_blocks(node, 1, signal=False)
        assert_equal(node.getblockcount(), 480)
        status, since = self.get_status(node)
        self.log.info(f"Block 480: Status={status}, Since={since}")
        assert_equal(status, 'active')
        assert_equal(since, 480)

        self.log.info("\n=== TEST 1 COMPLETE ===")
        self.log.info("Summary: max_activation_height=480 test passed")
        self.log.info("- Deployment activated at height 480 via forced lock-in at 360")
        self.log.info("- Mandatory signaling enforced during blocks 240-359 (BIP148-style)")
        self.log.info("- Non-signaling blocks rejected during enforcement window")
        self.log.info("- Non-signaling blocks accepted outside enforcement window")

        # Test 2: Deployment without max_height requires signaling
        self.log.info("\n\n=== TEST 2: Deployment without max_height requires signaling ===")
        node = self.nodes[1]

        # Period 0 (0-119): DEFINED
        self.log.info("\n--- Period 0 (blocks 0-119): DEFINED ---")
        self.mine_blocks(node, 119, signal=False)
        assert_equal(node.getblockcount(), 119)
        status, since = self.get_status(node)
        self.log.info(f"Block 119: Status={status}")
        assert_equal(status, 'defined')

        # Mine period 1 (blocks 120-239) without signaling - should transition to STARTED
        self.log.info("Mining period 1 (blocks 120-239) without signaling...")
        self.mine_blocks(node, 120, signal=False)
        assert_equal(node.getblockcount(), 239)
        status, since = self.get_status(node)
        self.log.info(f"Block 239: Status={status}")
        assert_equal(status, 'started')

        # Mine period 2 (blocks 240-359) without signaling - should remain STARTED
        self.log.info("Mining period 2 (blocks 240-359) without signaling...")
        self.mine_blocks(node, 120, signal=False)
        status, since = self.get_status(node)
        self.log.info(f"Block 359: Status={status}")
        assert_equal(status, 'started')  # Should NOT lock in without signaling

        # Mine period 3 (blocks 360-479) without signaling - should remain STARTED
        self.log.info("Mining period 3 (blocks 360-479) without signaling...")
        self.mine_blocks(node, 120, signal=False)
        status, since = self.get_status(node)
        self.log.info(f"Block 479: Status={status}")
        assert_equal(status, 'started')  # Still STARTED without signaling

        self.log.info("\n=== TEST 2 COMPLETE ===")
        self.log.info("SUCCESS: Deployment did NOT activate without signaling (no max_height)")

        # Test 3: Early activation via signaling before max_height
        self.log.info("\n\n=== TEST 3: Early activation via signaling before max_height ===")
        node = self.nodes[2]

        # Period 0 (0-119): DEFINED
        self.log.info("\n--- Period 0 (blocks 0-119): DEFINED ---")
        self.mine_blocks(node, 119, signal=False)
        assert_equal(node.getblockcount(), 119)
        status, since = self.get_status(node)
        self.log.info(f"Block 119: Status={status}")
        assert_equal(status, 'defined')

        # Mine period 1 (blocks 120-239) with 100% signaling
        self.log.info("Mining period 1 (blocks 120-239) with 100% signaling...")
        self.mine_blocks(node, 120, signal=True)
        assert_equal(node.getblockcount(), 239)
        status, since = self.get_status(node)
        self.log.info(f"Block 239: Status={status}")
        assert_equal(status, 'started')

        # Mine period 2 (blocks 240-359) with signaling - should lock in
        self.log.info("Mining period 2 (blocks 240-359) with signaling - should lock in...")
        self.mine_blocks(node, 120, signal=True)
        assert_equal(node.getblockcount(), 359)
        status, since = self.get_status(node)
        self.log.info(f"Block 359: Status={status}, Since={since}")
        assert_equal(status, 'locked_in')
        assert_equal(since, 240)  # Locked in at start of period 2 via signaling threshold

        # Mine block 360 - should activate via signaling (well before max_height 480)
        self.log.info("Mining block 360 - should activate via signaling (before max_height 480)...")
        self.mine_blocks(node, 1, signal=True)
        assert_equal(node.getblockcount(), 360)
        status, since = self.get_status(node)
        self.log.info(f"Block 360: Status={status}, Since={since}")
        assert_equal(status, 'active')
        assert_equal(since, 360)

        self.log.info("\n=== TEST 3 COMPLETE ===")
        self.log.info("SUCCESS: Deployment activated early via signaling (at 360, before max_height 480)")

        # Test 4: Verify ACTIVE state is permanent
        self.log.info("\n\n=== TEST 4: Verify ACTIVE state is permanent ===")
        node = self.nodes[3]

        # Activate via max_height (max_height=360)
        # Mine to block 119 (period 0) without signaling
        self.log.info("Mining period 0 (blocks 0-119) without signaling...")
        self.mine_blocks(node, 119, signal=False)
        assert_equal(node.getblockcount(), 119)

        # Mine through enforcement window (blocks 120-239) WITH signaling
        # Enforcement window for max_height=360 is [120, 240)
        self.log.info("Mining blocks 120-239 with signaling (enforcement window)...")
        self.mine_blocks(node, 120, signal=True)
        assert_equal(node.getblockcount(), 239)
        status, since = self.get_status(node)
        assert_equal(status, 'started')

        # Mine period 2 (blocks 240-359) - will force lock-in at 240 (360 - 120)
        self.log.info("Mining period 2 (blocks 240-359) - forced lock-in at end...")
        self.mine_blocks(node, 120, signal=False)
        assert_equal(node.getblockcount(), 359)
        status, since = self.get_status(node)
        assert_equal(status, 'locked_in')

        # Mine block 360 - should activate
        self.log.info("Mining block 360 - should activate via max_height...")
        self.mine_blocks(node, 1, signal=False)
        assert_equal(node.getblockcount(), 360)
        status, since = self.get_status(node)
        self.log.info(f"Block 360: Status={status}, Since={since}")
        assert_equal(status, 'active')
        assert_equal(since, 360)

        # Mine 300 more blocks to verify permanence
        self.log.info("Mining 300 more blocks to verify ACTIVE state persists...")
        self.mine_blocks(node, 300, signal=False)
        assert_equal(node.getblockcount(), 660)
        status, since = self.get_status(node)
        self.log.info(f"Block 660: Status={status}, Since={since}")
        assert_equal(status, 'active')
        assert_equal(since, 360)

        self.log.info("\n=== TEST 4 COMPLETE ===")
        self.log.info("SUCCESS: Deployment remains ACTIVE permanently")

        # Test 5: Combined temporary deployment with max_height
        self.log.info("\n\n=== TEST 5: Temporary deployment with max_height ===")
        node = self.nodes[4]

        # This node has max_activation_height=360 AND active_duration=120
        # Should activate at 360 via max_height, then expire at 360+120=480
        # Mine to block 119 (period 0) without signaling
        self.log.info("Mining period 0 (blocks 0-119) without signaling...")
        self.mine_blocks(node, 119, signal=False)
        assert_equal(node.getblockcount(), 119)

        # Mine through enforcement window (blocks 120-239) WITH signaling
        # Enforcement window for max_height=360 is [120, 240)
        self.log.info("Mining blocks 120-239 with signaling (enforcement window)...")
        self.mine_blocks(node, 120, signal=True)
        assert_equal(node.getblockcount(), 239)
        status, since = self.get_status(node)
        self.log.info(f"Block 239: Status={status}")
        assert_equal(status, 'started')

        # Mine period 2 (blocks 240-359) - will force lock-in at 240 (360 - 120)
        self.log.info("Mining period 2 (blocks 240-359) - forced lock-in at end...")
        self.mine_blocks(node, 120, signal=False)
        assert_equal(node.getblockcount(), 359)
        status, since = self.get_status(node)
        self.log.info(f"Block 359: Status={status}")
        assert_equal(status, 'locked_in')

        # Mine block 360 - should activate via max_height
        self.log.info("Mining block 360 - should activate via max_height...")
        self.mine_blocks(node, 1, signal=False)
        assert_equal(node.getblockcount(), 360)
        status, since = self.get_status(node)
        self.log.info(f"Block 360: Status={status}, Since={since}")
        assert_equal(status, 'active')
        assert_equal(since, 360)

        # Mine through active period to block 479 (360+120-1)
        self.log.info("Mining through active period to block 479 (360+120-1)...")
        self.mine_blocks(node, 119, signal=False)
        assert_equal(node.getblockcount(), 479)
        status, since = self.get_status(node)
        self.log.info(f"Block 479: Status={status}")
        assert_equal(status, 'active')

        # Mine block 480 (360+120) - deployment has expired
        # RPC status uses State(blockindex->pprev), so expired appears at tip 480
        self.log.info("Mining block 480 (360+120) - deployment should be expired...")
        self.mine_blocks(node, 1, signal=False)
        assert_equal(node.getblockcount(), 480)
        status, since = self.get_status(node)
        self.log.info(f"Block 480: Status={status}, Since={since}")
        assert_equal(status, 'expired')
        assert_equal(since, 480)

        # Mine block 481 - verify EXPIRED is terminal
        self.log.info("Mining block 481 - verify EXPIRED is terminal...")
        self.mine_blocks(node, 1, signal=False)
        assert_equal(node.getblockcount(), 481)
        status, since = self.get_status(node)
        self.log.info(f"Block 481: Status={status}")
        assert_equal(status, 'expired')

        self.log.info("\n=== TEST 5 COMPLETE ===")
        self.log.info("SUCCESS: Temporary deployment with max_height activated and expired correctly")

        # Test 6: Custom per-deployment threshold
        self.log.info("\n\n=== TEST 6: Custom per-deployment threshold (50% = 60/120 blocks) ===")
        node = self.nodes[5]

        # This node has threshold=60 (50% of 120 blocks)
        # Default regtest threshold is 90 (75%), but this deployment should activate at 60

        # Period 0 (0-119): DEFINED
        self.log.info("Mining period 0 (blocks 0-119) without signaling...")
        self.mine_blocks(node, 119, signal=False)
        assert_equal(node.getblockcount(), 119)
        status, _ = self.get_status(node)
        assert_equal(status, 'defined')

        # Block 120: Transition to STARTED
        self.log.info("Mining block 120 to transition to STARTED...")
        self.mine_blocks(node, 1, signal=False)
        assert_equal(node.getblockcount(), 120)
        status, since = self.get_status(node)
        self.log.info(f"Block 120: Status={status}, Since={since}")
        assert_equal(status, 'started')
        assert_equal(since, 120)

        # Period 1 (120-239): Mine exactly 60 signaling blocks (50%)
        # With custom threshold of 60, this should be enough to lock in
        self.log.info("Mining period 1 with exactly 60 signaling blocks (50%)...")
        self.mine_blocks(node, 60, signal=True)   # 60 signaling blocks
        self.mine_blocks(node, 59, signal=False)  # 59 non-signaling blocks
        assert_equal(node.getblockcount(), 239)
        status, since = self.get_status(node)
        self.log.info(f"Block 239: Status={status}")
        assert_equal(status, 'started')  # Still started until next period boundary

        # Block 240: Should transition to LOCKED_IN (threshold met in previous period)
        self.log.info("Mining block 240 to check lock-in...")
        self.mine_blocks(node, 1, signal=False)
        assert_equal(node.getblockcount(), 240)
        status, since = self.get_status(node)
        self.log.info(f"Block 240: Status={status}, Since={since}")
        assert_equal(status, 'locked_in')
        assert_equal(since, 240)

        # Mine through locked_in period to activate
        self.log.info("Mining through locked_in period (241-359)...")
        self.mine_blocks(node, 119, signal=False)
        assert_equal(node.getblockcount(), 359)
        status, since = self.get_status(node)
        assert_equal(status, 'locked_in')

        # Block 360: Should transition to ACTIVE
        self.log.info("Mining block 360 to activate...")
        self.mine_blocks(node, 1, signal=False)
        assert_equal(node.getblockcount(), 360)
        status, since = self.get_status(node)
        self.log.info(f"Block 360: Status={status}, Since={since}")
        assert_equal(status, 'active')
        assert_equal(since, 360)

        self.log.info("\n=== TEST 6 COMPLETE ===")
        self.log.info("SUCCESS: Deployment activated with custom 50% threshold (60/120 blocks)")
        self.log.info("- Custom threshold overrode default 75% threshold")
        self.log.info("- Lock-in occurred with only 50% signaling support")


if __name__ == '__main__':
    MaxActivationHeightTest(__file__).main()
