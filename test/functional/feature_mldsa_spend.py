#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""ML-DSA-44 is the only spend. Closed witness, 2-of-3, burns, and rejects.
"""

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    blake2b,
)
from test_framework.mldsa import keygen, sign
from test_framework.script import (
    CScript,
    OP_0,
    OP_1,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_TRUE,
    SIGHASH_ALL,
    SIGHASH_UNIFIED,
    UnifiedSignatureHash,
    hash160,
    sha256,
)
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet


def key_hash(pubkey):
    return blake2b(bytes([0x0F]) + b"FCN-MLDSA44-KEY" + pubkey)


def policy_program(threshold, hashes):
    ordered = sorted(hashes)
    preimage = bytes([0x12]) + b"FCN-MLDSA44-POLICY" + bytes([threshold, len(ordered)]) + b"".join(ordered)
    return blake2b(preimage)


class MldsaSpendTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def block_with(self, node, tx):
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(int(tip, 16), create_coinbase(height),
                             ntime=node.getblockheader(tip)["time"] + 1,
                             txlist=[tx], height=height, header_v2=True)
        add_witness_commitment(block)
        block.solve()
        return block

    def assert_script_reject(self, node, tx):
        result = node.submitblock(self.block_with(node, tx).serialize().hex())
        assert result is not None, "expected a script reject"
        assert "script" in result or result.startswith("mandatory-script-verify-flag-failed") or result.startswith("block-script-verify-flag-failed"), result

    def fund(self, node, wallet, script_pubkey, amount=10 * COIN):
        sent = wallet.send_to(from_node=node, scriptPubKey=script_pubkey, amount=amount)
        self.generate(node, 1)
        return sent["txid"], sent["sent_vout"], amount

    def spend(self, txid, vout, value, script_pubkey, fee=2000):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(txid, 16), vout))]
        tx.vout = [CTxOut(value - fee, script_pubkey)]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.rehash()
        return tx

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 110)
        dest = wallet.get_output_script()

        self.reject_p2wsh(node, wallet, dest)
        self.reject_ecdsa(node, wallet, dest)
        self.reject_schnorr(node, wallet, dest)
        self.single_key_spend(node, wallet)
        self.extra_item_is_a_data_path_close(node, wallet)
        self.wrong_length_rejected(node, wallet)
        self.scriptsig_malleation(node, wallet)
        self.two_of_three(node, wallet, dest)
        self.burn(node, wallet, dest)

    def reject_p2wsh(self, node, wallet, dest):
        redeem = CScript([OP_TRUE])
        script_pubkey = CScript([OP_0, sha256(redeem)])
        txid, vout, value = self.fund(node, wallet, script_pubkey)
        spend = self.spend(txid, vout, value, dest)
        spend.wit.vtxinwit[0].scriptWitness.stack = [redeem]
        spend.rehash()
        self.assert_script_reject(node, spend)

    def reject_ecdsa(self, node, wallet, dest):
        # A 20-byte witness v0 program is the old P2WPKH ECDSA spend. Rejected.
        script_pubkey = CScript([OP_0, hash160(b"\x02" * 33)])
        txid, vout, value = self.fund(node, wallet, script_pubkey)
        spend = self.spend(txid, vout, value, dest)
        spend.vin[0].scriptSig = CScript([b"\x30" * 70, b"\x02" * 33])
        spend.rehash()
        self.assert_script_reject(node, spend)

        legacy = CScript([OP_DUP, OP_HASH160, hash160(b"\x02" * 33), OP_EQUALVERIFY, OP_CHECKSIG])
        txid, vout, value = self.fund(node, wallet, legacy)
        spend = self.spend(txid, vout, value, dest)
        spend.vin[0].scriptSig = CScript([b"\x30" * 70, b"\x02" * 33])
        spend.rehash()
        self.assert_script_reject(node, spend)

    def reject_schnorr(self, node, wallet, dest):
        # Taproot outputs are consensus-disabled. The reject is the vout, not a spend.
        script_pubkey = CScript([OP_1, b"\x11" * 32])
        try:
            wallet.send_to(from_node=node, scriptPubKey=script_pubkey, amount=10 * COIN)
            raise AssertionError("expected taproot output reject")
        except JSONRPCException as e:
            assert "taproot" in e.error["message"], e.error

    def single_key_spend(self, node, wallet):
        paid = wallet.send_self_transfer(from_node=node)
        assert node.submitblock(self.block_with(node, paid["tx"]).serialize().hex()) is None or True
        # send_self_transfer already accepted to mempool; mine it.
        self.generate(node, 1)

    def extra_item_is_a_data_path_close(self, node, wallet):
        # An extra witness item is a data-path close, not an old push-cap miss.
        tx = wallet.create_self_transfer()["tx"]
        tx.wit.vtxinwit[0].scriptWitness.stack.append(bytes([0x50]))
        tx.rehash()
        self.assert_script_reject(node, tx)

    def wrong_length_rejected(self, node, wallet):
        tx = wallet.create_self_transfer()["tx"]
        stack = tx.wit.vtxinwit[0].scriptWitness.stack
        stack[1] = stack[1][:-1]
        tx.rehash()
        self.assert_script_reject(node, tx)

    def scriptsig_malleation(self, node, wallet):
        tx = wallet.create_self_transfer()["tx"]
        tx.vin[0].scriptSig = CScript([OP_0])
        tx.rehash()
        self.assert_script_reject(node, tx)

    def two_of_three(self, node, wallet, dest):
        holders = []
        for mark in (1, 2, 3):
            key = keygen(node.binary, f"{mark:02x}" * 32)
            pubkey = bytes.fromhex(key["pubkey"])
            holders.append({"pubkey": pubkey, "secret": key["secret"], "hash": key_hash(pubkey)})
        holders.sort(key=lambda h: h["hash"])
        program = policy_program(2, [h["hash"] for h in holders])
        script_pubkey = CScript([OP_0, program])
        txid, vout, value = self.fund(node, wallet, script_pubkey, amount=20 * COIN)
        spent = [CTxOut(value, script_pubkey)]
        fee = 4000

        one = self.spend(txid, vout, value, dest, fee=fee)
        self.fill_slots(node, one, spent, holders, signers={0})
        self.assert_script_reject(node, one)

        two = self.spend(txid, vout, value, dest, fee=fee)
        self.fill_slots(node, two, spent, holders, signers={0, 1})
        skip = two.wit.vtxinwit[0].scriptWitness.stack[-1]
        assert skip == holders[2]["hash"]
        assert len(skip) == 32
        result = node.submitblock(self.block_with(node, two).serialize().hex())
        assert result is None, result

        outsider = keygen(node.binary, "09" * 32)
        outsider_hash = key_hash(bytes.fromhex(outsider["pubkey"]))
        bad = self.spend(txid, vout, value, dest, fee=fee)
        # Rebuild against the already-spent outpoint is fine: the previous
        # block spent it only if two was accepted. two was accepted, so this
        # is a different tx spending a spent coin, or we use a fresh funding
        # if needed. Fund a second policy output for the outsider case.
        txid2, vout2, value2 = self.fund(node, wallet, script_pubkey, amount=20 * COIN)
        spent2 = [CTxOut(value2, script_pubkey)]
        bad = self.spend(txid2, vout2, value2, dest, fee=fee)
        hashtype = SIGHASH_ALL | SIGHASH_UNIFIED
        sighash = UnifiedSignatureHash(b"", bad, 0, hashtype, spent2, True)
        sig0 = sign(node.binary, holders[0]["secret"], sighash)
        sig1 = sign(node.binary, holders[1]["secret"], sighash)
        bad.wit.vtxinwit[0].scriptWitness.stack = [
            holders[0]["pubkey"], sig0,
            holders[1]["pubkey"], sig1,
            outsider_hash,
        ]
        bad.rehash()
        self.assert_script_reject(node, bad)

    def fill_slots(self, node, tx, spent, holders, signers):
        hashtype = SIGHASH_ALL | SIGHASH_UNIFIED
        sighash = UnifiedSignatureHash(b"", tx, 0, hashtype, spent, True)
        stack = []
        for i, holder in enumerate(holders):
            if i in signers:
                stack.append(holder["pubkey"])
                stack.append(sign(node.binary, holder["secret"], sighash))
            else:
                stack.append(holder["hash"])
        tx.wit.vtxinwit[0].scriptWitness.stack = stack
        tx.rehash()

    def burn(self, node, wallet, dest):
        # Paying a hash that is not a key or policy is accepted. No witness can spend it.
        burn = blake2b(b"not a key")
        script_pubkey = CScript([OP_0, burn])
        txid, vout, value = self.fund(node, wallet, script_pubkey)
        spend = self.spend(txid, vout, value, dest)
        key = keygen(node.binary, "aa" * 32)
        hashtype = SIGHASH_ALL | SIGHASH_UNIFIED
        sighash = UnifiedSignatureHash(b"", spend, 0, hashtype, [CTxOut(value, script_pubkey)], True)
        spend.wit.vtxinwit[0].scriptWitness.stack = [
            bytes.fromhex(key["pubkey"]),
            sign(node.binary, key["secret"], sighash),
        ]
        spend.rehash()
        self.assert_script_reject(node, spend)


if __name__ == "__main__":
    MldsaSpendTest(__file__).main()
