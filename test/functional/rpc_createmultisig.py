#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""createmultisig still emits P2SH/P2WSH. Those are not a valid payment."""

import json
import os

from test_framework.address import address_to_scriptpubkey, base58_to_byte, byte_to_base58
from test_framework.authproxy import JSONRPCException
from test_framework.descriptors import descsum_create
from test_framework.key import ECPubKey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_0
from test_framework.script_util import keys_to_multisig_script, script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


class RpcCreateMultiSigTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False

    def create_keys(self, num_keys):
        self.pub = []
        self.priv = []
        for _ in range(num_keys):
            privkey, pubkey = generate_keypair(wif=True)
            self.pub.append(pubkey.hex())
            self.priv.append(privkey)

    def assert_not_a_payment(self, address, redeem_script):
        node = self.nodes[0]
        script = address_to_scriptpubkey(address)
        try:
            sent = self.wallet.send_to(from_node=node, scriptPubKey=script, amount=30_000)
        except JSONRPCException as exc:
            assert exc.error["message"], exc.error
            return
        self.generate(node, 1)
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(int(sent["txid"], 16), sent["sent_vout"]))]
        spend.vout = [CTxOut(20_000, self.wallet.get_output_script())]
        spend.wit.vtxinwit = [CTxInWitness()]
        redeem = bytes.fromhex(redeem_script)
        if script == script_to_p2wsh_script(redeem):
            spend.wit.vtxinwit[0].scriptWitness.stack = [b"", redeem]
        elif bytes(script)[:1] == bytes(CScript([OP_0]))[:1] and len(script) == 34:
            spend.wit.vtxinwit[0].scriptWitness.stack = [b"", redeem]
        else:
            spend.vin[0].scriptSig = CScript([b"", redeem])
        spend.rehash()
        result = node.testmempoolaccept([spend.serialize().hex()])[0]
        assert_equal(result["allowed"], False)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 110)
        self.create_keys(21)

        for nsigs, nkeys in ((2, 3), (1, 1)):
            for address_type in ("bech32", "p2sh-segwit", "legacy"):
                if address_type in ("legacy", "p2sh-segwit"):
                    assert_raises_rpc_error(-5, "Unknown address type", node.createmultisig, nsigs, self.pub[:nkeys], address_type)
                    continue
                created = node.createmultisig(nsigs, self.pub[:nkeys], address_type)
                self.assert_not_a_payment(created["address"], created["redeemScript"])

        assert_raises_rpc_error(-5, "Unknown address type", node.createmultisig, 16, self.pub[:20], "legacy")
        assert_raises_rpc_error(-8, "Number of keys involved in the multisignature address creation > 20", node.createmultisig, 16, self.pub, "bech32")
        assert_raises_rpc_error(-5, "Unknown address type", node.createmultisig, 2, self.pub[:2], "bech32m")

        self.log.info("Check correct encoding of multisig script for all n (1..20)")
        for nkeys in range(1, 21):
            keys = [self.pub[0]] * nkeys
            expected = keys_to_multisig_script(keys, k=nkeys)
            created = node.createmultisig(nrequired=nkeys, keys=keys, address_type="bech32")
            assert_equal(created["redeemScript"], expected.hex())
            self.assert_not_a_payment(created["address"], created["redeemScript"])

        self.test_mixing_uncompressed_and_compressed_keys()
        self.test_sortedmulti_descriptors_bip67()

    def test_mixing_uncompressed_and_compressed_keys(self):
        self.log.info("Mixed compressed and uncompressed multisigs fall back to legacy, which is not a payment")
        pubs = [generate_keypair()[1].hex() for _ in range(3)]
        pk_obj = ECPubKey()
        pk_obj.set(bytes.fromhex(pubs[2]))
        pk_obj.compressed = False
        pubs[2] = pk_obj.get_bytes().hex()
        assert_raises_rpc_error(-5, "Unknown address type", self.nodes[0].createmultisig, 2, pubs, "legacy")
        created = self.nodes[0].createmultisig(nrequired=2, keys=pubs, address_type="bech32")
        assert_equal(created["warnings"], ["Unable to make chosen address type, please ensure no uncompressed public keys are present."])
        self.assert_not_a_payment(created["address"], created["redeemScript"])

    def test_sortedmulti_descriptors_bip67(self):
        self.log.info("Testing sortedmulti descriptors with BIP 67 test vectors")
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "data/rpc_bip67.json"), encoding="utf-8") as f:
            vectors = json.load(f)
        for vector in vectors:
            key_str = ",".join(vector["keys"])
            desc = descsum_create("sh(sortedmulti(2,{}))".format(key_str))
            payload, version = base58_to_byte(vector["address"])
            assert_equal(version, 196)
            address = byte_to_base58(payload, 197)
            assert_equal(self.nodes[0].deriveaddresses(desc)[0], address)
            self.assert_not_a_payment(address, keys_to_multisig_script([bytes.fromhex(k) for k in vector["sorted_keys"]], k=2).hex())


if __name__ == "__main__":
    RpcCreateMultiSigTest(__file__).main()
