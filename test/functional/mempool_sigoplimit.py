#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""P2WSH and P2SH CHECKSIG layouts are refused. Sigops-vsize is not a live lever."""

from test_framework.authproxy import JSONRPCException
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import (
    CScript,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_ENDIF,
    OP_FALSE,
    OP_IF,
    OP_TRUE,
)
from test_framework.script_util import script_to_p2sh_script, script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class BytesPerSigOpTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def try_fund(self, script, amount=5_000_000):
        try:
            return self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script, amount=amount)
        except JSONRPCException as exc:
            assert exc.error["message"], exc.error
            return None

    def assert_spend_refused(self, fund, witness_script=None, script_sig=None):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(fund["txid"], 16), fund["sent_vout"]))]
        tx.vout = [CTxOut(4_500_000, self.wallet.get_output_script())]
        if script_sig is not None:
            tx.vin[0].scriptSig = script_sig
        if witness_script is not None:
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(witness_script)]
        tx.rehash()
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(result["allowed"], False)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        witness_script = CScript([OP_FALSE, OP_IF, OP_CHECKMULTISIG, OP_CHECKSIG, OP_ENDIF, OP_TRUE])
        p2wsh = script_to_p2wsh_script(witness_script)
        funded = self.try_fund(p2wsh)
        if funded is not None:
            self.log.info("P2WSH CHECKSIG/CHECKMULTISIG spend is refused")
            self.assert_spend_refused(funded, witness_script=witness_script)

        packed = CScript([OP_CHECKSIG, OP_TRUE])
        p2sh = script_to_p2sh_script(packed)
        funded_p2sh = self.try_fund(p2sh, amount=5_000_000)
        if funded_p2sh is not None:
            self.log.info("P2SH CHECKSIG spend is refused")
            self.assert_spend_refused(funded_p2sh, script_sig=CScript([b"", packed]))


if __name__ == "__main__":
    BytesPerSigOpTest(__file__).main()
