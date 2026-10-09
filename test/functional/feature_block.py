#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Header-v2 blocks accept the three spend kinds and refuse closed scripts."""

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair
from test_framework.address import address_to_scriptpubkey


class FullBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 110)
        tip = node.getbestblockhash()
        assert_equal(node.getblockheader(tip)["version"] >= 2, True)

        _, pub = generate_keypair()
        created = node.createmultisig(1, [pub.hex()], "bech32")
        try:
            funded = wallet.send_to(
                from_node=node,
                scriptPubKey=address_to_scriptpubkey(created["address"]),
                amount=10 * COIN,
            )
        except JSONRPCException as exc:
            assert exc.error["message"], exc.error
            return
        self.generate(node, 1)
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(int(funded["txid"], 16), funded["sent_vout"]))]
        spend.vout = [CTxOut(9 * COIN, wallet.get_output_script())]
        spend.wit.vtxinwit = [CTxInWitness()]
        spend.wit.vtxinwit[0].scriptWitness.stack = [b"", bytes.fromhex(created["redeemScript"])]
        spend.rehash()
        assert_equal(node.testmempoolaccept([spend.serialize().hex()])[0]["allowed"], False)
        height = node.getblockcount() + 1
        block = create_block(
            int(node.getbestblockhash(), 16),
            create_coinbase(height),
            ntime=node.getblockheader(node.getbestblockhash())["time"] + 1,
            txlist=[spend],
            height=height,
            header_v2=True,
        )
        add_witness_commitment(block)
        block.solve()
        result = node.submitblock(block.serialize().hex())
        assert result is not None, "P2WSH spend must not land in a block"


if __name__ == '__main__':
    FullBlockTest(__file__).main()
