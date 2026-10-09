#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""P2SH and P2WSH CHECKMULTISIG layouts are refused. NULLDUMMY is not a live opcode."""

from test_framework.address import address_to_scriptpubkey
from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_0
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


class NULLDUMMYTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def block_with(self, tx):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(
            int(tip, 16),
            create_coinbase(height),
            ntime=node.getblockheader(tip)["time"] + 1,
            txlist=[tx],
            height=height,
            header_v2=True,
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def assert_refused(self, tx):
        node = self.nodes[0]
        result = node.testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(result["allowed"], False)
        block_result = node.submitblock(self.block_with(tx).serialize().hex())
        assert block_result is not None, "closed CHECKMULTISIG layout must not land in a block"

    def try_fund(self, script):
        try:
            return self.wallet.send_to(from_node=self.nodes[0], scriptPubKey=script, amount=10 * COIN)
        except JSONRPCException as exc:
            assert exc.error["message"], exc.error
            return None

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 110)
        _, pubkey = generate_keypair()
        assert_raises_rpc_error(-5, "Unknown address type", node.createmultisig, 1, [pubkey.hex()], "legacy")
        witness = node.createmultisig(1, [pubkey.hex()], "bech32")

        self.log.info("P2WSH CHECKMULTISIG is refused")
        funded = self.try_fund(address_to_scriptpubkey(witness["address"]))
        if funded is not None:
            self.generate(node, 1)
            redeem = bytes.fromhex(witness["redeemScript"])
            spend = CTransaction()
            spend.vin = [CTxIn(COutPoint(int(funded["txid"], 16), funded["sent_vout"]))]
            spend.vout = [CTxOut(9 * COIN, self.wallet.get_output_script())]
            spend.wit.vtxinwit = [CTxInWitness()]
            spend.wit.vtxinwit[0].scriptWitness.stack = [b"", redeem]
            spend.rehash()
            self.assert_refused(spend)

        self.assert_closed_address_types(node)


if __name__ == '__main__':
    NULLDUMMYTest(__file__).main()
