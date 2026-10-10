#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Witness spend kinds keep the same txid when re-signed. They are not scriptSig-malleable."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.messages import (
    COIN,
    tx_from_hex,
)


class TxnMallTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def add_options(self, parser):
        self.add_wallet_options(parser)
        parser.add_argument("--mineblock", dest="mine_block", default=False, action="store_true",
                            help="Confirm the spend before re-signing")
        parser.add_argument("--segwit", dest="segwit", default=False, action="store_true",
                            help="Use the warned secp P2WPKH path")

    def setup_network(self):
        super().setup_network()
        self.disconnect_nodes(1, 2)

    def spend_utxo(self, utxo, outputs):
        inputs = [utxo]
        tx = self.nodes[0].createrawtransaction(inputs, outputs)
        tx = self.nodes[0].fundrawtransaction(tx)
        tx = self.nodes[0].signrawtransactionwithwallet(tx['hex'])
        assert_equal(tx["complete"], True)
        return self.nodes[0].sendrawtransaction(tx['hex'])

    def run_test(self):
        output_type = "secp" if self.options.segwit else "mldsa87"

        starting_balance = 1250
        for i in range(3):
            assert_equal(self.nodes[i].getbalance(), starting_balance)

        self.nodes[0].settxfee(.001)

        node0_address1 = self.nodes[0].getnewaddress(address_type=output_type)
        node0_utxo1 = self.create_outpoints(self.nodes[0], outputs=[{node0_address1: 1219}])[0]
        node0_tx1 = self.nodes[0].gettransaction(node0_utxo1['txid'])
        self.nodes[0].lockunspent(False, [node0_utxo1])

        node0_address2 = self.nodes[0].getnewaddress(address_type=output_type)
        node0_utxo2 = self.create_outpoints(self.nodes[0], outputs=[{node0_address2: 29}])[0]
        node0_tx2 = self.nodes[0].gettransaction(node0_utxo2['txid'])

        assert_equal(self.nodes[0].getbalance(),
                     starting_balance + node0_tx1["fee"] + node0_tx2["fee"])

        node1_address = self.nodes[1].getnewaddress()

        txid1 = self.spend_utxo(node0_utxo1, {node1_address: 40})
        txid2 = self.spend_utxo(node0_utxo2, {node1_address: 20})

        rawtx1 = self.nodes[0].getrawtransaction(txid1, 1)
        clone_inputs = [{"txid": rawtx1["vin"][0]["txid"], "vout": rawtx1["vin"][0]["vout"], "sequence": rawtx1["vin"][0]["sequence"]}]
        clone_outputs = {rawtx1["vout"][0]["scriptPubKey"]["address"]: rawtx1["vout"][0]["value"],
                         rawtx1["vout"][1]["scriptPubKey"]["address"]: rawtx1["vout"][1]["value"]}
        clone_locktime = rawtx1["locktime"]
        clone_raw = self.nodes[0].createrawtransaction(clone_inputs, clone_outputs, clone_locktime)

        clone_tx = tx_from_hex(clone_raw)
        if (rawtx1["vout"][0]["value"] == 40 and clone_tx.vout[0].nValue != 40*COIN or rawtx1["vout"][0]["value"] != 40 and clone_tx.vout[0].nValue == 40*COIN):
            (clone_tx.vout[0], clone_tx.vout[1]) = (clone_tx.vout[1], clone_tx.vout[0])

        tx1_clone = self.nodes[0].signrawtransactionwithwallet(clone_tx.serialize().hex())
        assert_equal(tx1_clone["complete"], True)
        assert_equal(self.nodes[0].decoderawtransaction(tx1_clone["hex"])["txid"], txid1)

        if self.options.mine_block:
            self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_blocks(self.nodes[0:2]))

        tx1 = self.nodes[0].gettransaction(txid1)
        tx2 = self.nodes[0].gettransaction(txid2)

        expected = starting_balance + node0_tx1["fee"] + node0_tx2["fee"]
        if self.options.mine_block:
            expected += 50
        expected += tx1["amount"] + tx1["fee"]
        expected += tx2["amount"] + tx2["fee"]
        assert_equal(self.nodes[0].getbalance(), expected)

        if self.options.mine_block:
            assert_equal(tx1["confirmations"], 1)
            assert_equal(tx2["confirmations"], 1)
        else:
            assert_equal(tx1["confirmations"], 0)
            assert_equal(tx2["confirmations"], 0)

        # Isolated miner accepts the same txid (not a malleated clone).
        self.nodes[2].sendrawtransaction(node0_tx1["hex"])
        txid1_clone = self.nodes[2].sendrawtransaction(tx1_clone["hex"])
        assert_equal(txid1, txid1_clone)
        self.generate(self.nodes[2], 1, sync_fun=self.no_op)

        self.connect_nodes(1, 2)
        self.nodes[2].sendrawtransaction(node0_tx2["hex"])
        self.nodes[2].sendrawtransaction(tx2["hex"])
        self.generate(self.nodes[2], 1)

        tx1 = self.nodes[0].gettransaction(txid1)
        tx2 = self.nodes[0].gettransaction(txid2)
        assert tx1["confirmations"] >= 1
        assert tx2["confirmations"] >= 1


if __name__ == '__main__':
    TxnMallTest(__file__).main()
