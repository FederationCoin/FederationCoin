#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test mempool acceptance in case of an already known transaction
with identical non-witness data but different witness.
"""

from copy import deepcopy
from decimal import Decimal

from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.mldsa import key_hash, keygen, policy_program, sign_slots
from test_framework.p2p import P2PTxInvStore
from test_framework.script import (
    CScript,
    OP_0,
    SIGHASH_ALL,
    SIGHASH_UNIFIED,
    UnifiedSignatureHash,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.wallet import MiniWallet


class MempoolWtxidTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.log.info('Start with empty mempool and mature MiniWallet coinbases')
        self.generate(wallet, 101)
        assert_equal(node.getmempoolinfo()['size'], 0)

        keys = [keygen(node.binary, "22" * 32), keygen(node.binary, "33" * 32)]
        keys.sort(key=lambda k: key_hash(k["pubkey"]))
        program = policy_program(1, [key_hash(k["pubkey"]) for k in keys])
        script_pubkey = CScript([OP_0, program])

        self.log.info("Submit parent paying a 1-of-2 policy")
        utxo = wallet.get_utxo()
        parent = CTransaction()
        parent.vin.append(CTxIn(COutPoint(int(utxo['txid'], 16), utxo['vout']), b""))
        parent.vout.append(CTxOut(int((utxo['value'] - Decimal("0.0001")) * COIN), script_pubkey))
        wallet.sign_tx(parent, [CTxOut(int(utxo['value'] * COIN), wallet._scriptPubKey)])
        parent_txid = node.sendrawtransaction(hexstring=parent.serialize().hex(), maxfeerate=0)
        self.generate(node, 1)

        peer_wtxid_relay = node.add_p2p_connection(P2PTxInvStore())

        spent = [parent.vout[0]]
        child_one = CTransaction()
        child_one.vin.append(CTxIn(COutPoint(int(parent_txid, 16), 0), b""))
        child_one.vout.append(CTxOut(parent.vout[0].nValue - 20_000, wallet._scriptPubKey))
        child_one.wit.vtxinwit.append(CTxInWitness())
        sighash = UnifiedSignatureHash(b"", child_one, 0, SIGHASH_ALL | SIGHASH_UNIFIED, spent, True)
        child_one.wit.vtxinwit[0].scriptWitness.stack = sign_slots(node.binary, sighash, keys, 0)
        child_one_wtxid = child_one.getwtxid()
        child_one_txid = child_one.rehash()

        child_two = deepcopy(child_one)
        child_two.wit.vtxinwit[0].scriptWitness.stack = sign_slots(node.binary, sighash, keys, 1)
        child_two_wtxid = child_two.getwtxid()
        child_two_txid = child_two.rehash()

        assert_equal(child_one_txid, child_two_txid)
        assert child_one_wtxid != child_two_wtxid

        self.log.info("Submit child_one to the mempool")
        txid_submitted = node.sendrawtransaction(child_one.serialize().hex())
        assert_equal(node.getmempoolentry(txid_submitted)['wtxid'], child_one_wtxid)

        peer_wtxid_relay.wait_for_broadcast([child_one_wtxid])
        assert_equal(node.getmempoolinfo()["unbroadcastcount"], 0)

        expected = {
            "txid": child_one_txid,
            "wtxid": child_one_wtxid,
            "allowed": False,
            "reject-reason": "txn-already-in-mempool",
            "reject-details": "txn-already-in-mempool",
        }
        result = node.testmempoolaccept([child_one.serialize().hex()])[0]
        result.pop('usage')
        assert_equal(result, expected)

        expected = {
            "txid": child_two_txid,
            "wtxid": child_two_wtxid,
            "allowed": False,
            "reject-reason": "txn-same-nonwitness-data-in-mempool",
            "reject-details": "txn-same-nonwitness-data-in-mempool",
        }
        result = node.testmempoolaccept([child_two.serialize().hex()])[0]
        result.pop('usage')
        assert_equal(result, expected)

        node.sendrawtransaction(child_one.serialize().hex())

        self.log.info("Connect another peer that hasn't seen child_one before")
        peer_wtxid_relay_2 = node.add_p2p_connection(P2PTxInvStore())

        self.log.info("Submit child_two to the mempool")
        node.sendrawtransaction(child_two.serialize().hex())

        peer_wtxid_relay_2.wait_for_broadcast([child_one_wtxid])
        assert_equal(node.getmempoolinfo()["unbroadcastcount"], 0)


if __name__ == '__main__':
    MempoolWtxidTest(__file__).main()
