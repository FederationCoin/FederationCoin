#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""combinerawtransaction merges two Dilithium 44 slot partials."""

from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.mldsa import key_hash, keygen, policy_program, sign_slots
from test_framework.script import (
    CScript,
    OP_0,
    SIGHASH_ALL,
    SIGHASH_UNIFIED,
    UnifiedSignatureHash,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class CombineRawTransactionUnifiedTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 110)

        keys = [keygen(node.binary, f"{mark:02x}" * 32) for mark in (1, 2)]
        keys.sort(key=lambda key: key_hash(key["pubkey"]))
        program = policy_program(2, [key_hash(key["pubkey"]) for key in keys])
        script_pubkey = CScript([OP_0, program])
        funded = wallet.send_to(from_node=node, scriptPubKey=script_pubkey, amount=20 * COIN)
        self.generate(node, 1)

        value = 20 * COIN
        fee = 100_000
        unsigned = CTransaction()
        unsigned.vin = [CTxIn(COutPoint(int(funded["txid"], 16), funded["sent_vout"]))]
        unsigned.vout = [CTxOut(value - fee, wallet.get_output_script())]
        unsigned.wit.vtxinwit = [CTxInWitness()]
        spent = [CTxOut(value, script_pubkey)]
        sighash = UnifiedSignatureHash(b"", unsigned, 0, SIGHASH_ALL | SIGHASH_UNIFIED, spent, True)
        assert sighash is not None

        partials = []
        for index in (0, 1):
            tx = CTransaction(unsigned)
            tx.wit.vtxinwit[0].scriptWitness.stack = sign_slots(node.binary, sighash, keys, index)
            tx.rehash()
            partials.append(tx.serialize().hex())

        assert partials[0] != partials[1]
        assert_raises_rpc_error(-22, "TX decode failed", node.combinerawtransaction, [partials[0], partials[1] + "00"])
        assert_raises_rpc_error(-22, "Missing transactions", node.combinerawtransaction, [])

        combined = node.combinerawtransaction(partials)
        result = node.testmempoolaccept([combined])[0]
        assert result["allowed"], result
        node.sendrawtransaction(combined)
        self.generate(node, 1)
        assert_raises_rpc_error(-25, "Input not found or already spent", node.combinerawtransaction, partials)


if __name__ == "__main__":
    CombineRawTransactionUnifiedTest(__file__).main()
