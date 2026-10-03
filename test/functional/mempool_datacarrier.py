#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test datacarrier functionality"""
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    MAX_OP_RETURN_RELAY,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_RETURN,
    taproot_construct,
)
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

from random import randbytes


class DataCarrierTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [
            ["-acceptnonstddatacarrier=1", "-datacarrierfullcount"],
            ["-datacarrier=0"],
            ["-datacarrier=1", f"-datacarriersize={MAX_OP_RETURN_RELAY - 1}"],
            ["-datacarrier=1", "-datacarriersize=2", "-acceptnonstddatacarrier=1", "-datacarrierfullcount"],
        ]

    def test_null_data_transaction(self, node: TestNode, data) -> None:
        # The transaction is rejected, so the coin stays available.
        utxo = self.wallet.get_utxo(mark_as_spent=False)
        tx = self.wallet.create_self_transfer(fee_rate=0, utxo_to_spend=utxo)["tx"]
        data = [] if data is None else [data]
        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN] + data)))
        tx.vout[0].nValue -= tx.get_vsize()  # simply pay 1sat/vbyte fee
        self.wallet.resign(tx)
        tx_hex = tx.serialize().hex()
        self.assert_mempool_rejected(node, tx_hex)

    def assert_mempool_rejected(self, node: TestNode, tx_hex: str) -> None:
        """Policy may reject the script before the consensus check. Either way it stays out."""
        try:
            self.wallet.sendrawtransaction(from_node=node, tx_hex=tx_hex)
        except JSONRPCException as exc:
            assert exc.error["code"] == -26
            message = exc.error["message"]
            assert "datacarrier" in message or "scriptpubkey" in message or "toolarge" in message, message
            return
        raise AssertionError("OP_RETURN was accepted")

    def submit_block_with(self, node: TestNode, tx: CTransaction):
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block = create_block(int(tip, 16), create_coinbase(height),
                             ntime=node.getblockheader(tip)["time"] + 1,
                             txlist=[tx], height=height, header_v2=True)
        add_witness_commitment(block)
        block.solve()
        return node.submitblock(block.serialize().hex())

    def test_opnet_funding_rejected(self) -> None:
        internal_key = b'\x01' * 32
        tap = taproot_construct(internal_key, [("leaf", CScript([OP_1]))])
        utxo = self.wallet.get_utxo()
        funding_tx = CTransaction()
        funding_tx.vin = [CTxIn(COutPoint(int(utxo['txid'], 16), utxo['vout']))]
        funding_value = int(utxo['value'] * 100_000_000) - 1000
        funding_tx.vout = [CTxOut(funding_value, tap.scriptPubKey)]
        funding_tx.version = 2
        self.wallet.sign_tx(funding_tx)
        funding_tx.rehash()
        assert_raises_rpc_error(
            -26, "bad-txns-vout-taproot-disabled",
            self.nodes[0].sendrawtransaction, funding_tx.serialize().hex(),
        )


    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        # By default, only 80 bytes are used for data (+1 for OP_RETURN, +2 for the pushdata opcodes).
        default_size_data = randbytes(MAX_OP_RETURN_RELAY - 3)
        too_long_data = randbytes(MAX_OP_RETURN_RELAY - 2)
        small_data = randbytes(MAX_OP_RETURN_RELAY - 4)
        one_byte = randbytes(1)
        zero_bytes = randbytes(0)

        self.log.info("A user OP_RETURN is rejected. An over-size script is rejected before that.")
        for node in self.nodes:
            self.test_null_data_transaction(node=node, data=default_size_data)
            self.test_null_data_transaction(node=node, data=small_data)
            self.test_null_data_transaction(node=node, data=None)
            self.test_null_data_transaction(node=node, data=zero_bytes)
            self.test_null_data_transaction(node=node, data=one_byte)
            self.test_null_data_transaction(node=node, data=too_long_data)

        self.log.info("Consensus rejects a user OP_RETURN. Policy flags do not reopen it.")
        utxo = self.wallet.get_utxo()
        tx = self.wallet.create_self_transfer(utxo_to_spend=utxo)["tx"]
        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN, b"pay"])))
        tx.rehash()
        assert_equal(self.submit_block_with(self.nodes[0], tx), "bad-txns-datacarrier")
        wide = self.wallet.create_self_transfer(utxo_to_spend=utxo)["tx"]
        wide.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN, b"x" * 81])))
        wide.rehash()
        assert_equal(self.submit_block_with(self.nodes[0], wide), "bad-txns-vout-script-toolarge")

        self.log.info("Testing that an OPNet taproot output is rejected.")
        self.test_opnet_funding_rejected()


if __name__ == '__main__':
    DataCarrierTest(__file__).main()
