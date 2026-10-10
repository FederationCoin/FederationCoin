#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that ignore_rejects cannot relax reduced-data (RDTS) consensus rules.

PolicyScriptChecks must stay at least as strict as ConsensusScriptChecks: once
RDTS is active its flags are consensus, so a script-verify-flag
ignore_rejects that clears them lets a transaction pass the former and fail the
latter. ConsensusScriptChecks treats that as a bug, logging "BUG! PLEASE REPORT
THIS!" and tripping an Assume() that aborts on ABORT_ON_FAILED_ASSUME builds.

They stay unrelaxable after the clock is moved far ahead too: there is no
expiry that turns the rules off.
"""

from test_framework.blocktools import (
    add_witness_commitment,
    create_block,
    create_coinbase,
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
    OP_TRUE,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

# ConsensusScriptChecks' "policy passed but consensus failed" alarm.
BUG_MSG = "BUG! PLEASE REPORT THIS!"

# Activate at the BLAKE2b fork inside the warmup. A later mock time
# must not turn the rules off.
ACTIVATION_HEIGHT = 100

# A witness push above 256 bytes. Legal without SCRIPT_VERIFY_REDUCED_DATA,
# illegal with it. Taproot outputs are rejected on this chain, so the check
# is a P2WSH spend rather than a tapscript.
VIOLATING_PUSH = b'\x42' * 300
WITNESS_SCRIPT = CScript([VIOLATING_PUSH, OP_DROP, OP_TRUE])

# Tokens that clear non-mandatory script flags. None of them may admit this spend.
CASES = [
    [],
    ["non-mandatory-script-verify-flag"],
    ["non-mandatory-script-verify-flag-upgradable"],
]


class RdtsIgnoreRejectsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            f'-testactivationheight=blake2b@{ACTIVATION_HEIGHT}',
        ]]

    def fund_oversized_push(self):
        """Mine a P2WSH output and return a spend whose witness pushes 300 bytes."""
        node = self.nodes[0]
        funding_tx = self.wallet.create_self_transfer()['tx']
        funding_tx.vout[0] = CTxOut(funding_tx.vout[0].nValue, script_to_p2wsh_script(WITNESS_SCRIPT))
        funding_tx.rehash()

        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(int(tip, 16), create_coinbase(height),
                             node.getblockheader(tip)['time'] + 1,
                             height=height, header_v2=True)
        block.vtx.append(funding_tx)
        add_witness_commitment(block)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)

        spending_tx = CTransaction()
        spending_tx.vin = [CTxIn(COutPoint(funding_tx.sha256, 0))]
        spending_tx.vout = [CTxOut(funding_tx.vout[0].nValue - 1000, CScript([OP_0, bytes(20)]))]
        spending_tx.wit.vtxinwit.append(CTxInWitness())
        spending_tx.wit.vtxinwit[0].scriptWitness.stack = [WITNESS_SCRIPT]
        spending_tx.rehash()
        return spending_tx

    def check_all_rejected(self):
        node = self.nodes[0]
        for ignore_rejects in CASES:
            tx = self.fund_oversized_push()
            # Reaching ConsensusScriptChecks as a policy pass is what logs BUG_MSG.
            with node.assert_debug_log([], unexpected_msgs=[BUG_MSG]):
                result = node.testmempoolaccept([tx.serialize().hex()], 0, ignore_rejects)[0]
            assert_equal(result['allowed'], False)
            self.log.info(f"  ignore_rejects={ignore_rejects}: rejected ({result['reject-reason']})")

    def rdts_active_for_next_block(self):
        info = self.nodes[0].getblockchaininfo()
        return info['blocks'] + 1 >= ACTIVATION_HEIGHT

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 110)  # coinbase maturity; crosses the fork

        assert_equal(self.rdts_active_for_next_block(), True)
        self.log.info(f"Deployment active at height {node.getblockcount()}")
        self.check_all_rejected()

        node.setmocktime(2000000000)
        self.generate(self.wallet, 12)
        assert_equal(self.rdts_active_for_next_block(), True)
        self.log.info(f"Rules still on after the clock moved, height {node.getblockcount()}")
        self.check_all_rejected()

        self.log.info("Genuinely policy-only flags are still ignorable")
        assert_equal(node.testmempoolaccept(
            [self.wallet.create_self_transfer()['hex']], 0,
            ["non-mandatory-script-verify-flag-cleanstack"])[0]['allowed'], True)


if __name__ == '__main__':
    RdtsIgnoreRejectsTest(__file__).main()
