#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.messages import (
    COIN,
    CTxOut,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mempool_util import assert_mempool_contents
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)
from test_framework.wallet import (
    MiniWallet,
)

class EphemeralDustTest(BitcoinTestFramework):
    def set_test_params(self):
        # Mempools should match via 1P1C p2p relay
        self.num_nodes = 2

        # Don't test trickling logic
        self.noban_tx_relay = True

    def add_output_to_create_multi_result(self, result, output_value=0):
        """ Add output without changing absolute tx fee
        """
        assert len(result["tx"].vout) > 0
        assert result["tx"].vout[0].nValue >= output_value
        result["tx"].vout.append(CTxOut(output_value, result["tx"].vout[0].scriptPubKey))
        # Take value from first output
        result["tx"].vout[0].nValue -= output_value
        self.wallet.resign(result["tx"])
        result["new_utxos"][0]["value"] = Decimal(result["tx"].vout[0].nValue) / COIN
        new_txid = result["tx"].rehash()
        result["txid"]  = new_txid
        result["wtxid"] = result["tx"].getwtxid()
        result["hex"] = result["tx"].serialize().hex()
        for new_utxo in result["new_utxos"]:
            new_utxo["txid"] = new_txid
            new_utxo["wtxid"] = result["tx"].getwtxid()

        result["new_utxos"].append({"txid": new_txid, "vout": len(result["tx"].vout) - 1, "value": Decimal(output_value) / COIN, "height": 0, "coinbase": False, "confirmations": 0})

    def create_ephemeral_dust_package(self, *, tx_version, dust_tx_fee=0, dust_value=0, num_dust_outputs=1, extra_sponsors=None):
        """Creates a 1P1C package containing ephemeral dust. By default, the parent transaction
           is zero-fee and creates a single zero-value dust output, and all of its outputs are
           spent by the child."""
        dusty_tx = self.wallet.create_self_transfer_multi(fee_per_output=dust_tx_fee, version=tx_version)
        for _ in range(num_dust_outputs):
            self.add_output_to_create_multi_result(dusty_tx, dust_value)

        extra_sponsors = extra_sponsors or []
        sweep_tx = self.wallet.create_self_transfer_multi(
            utxos_to_spend=dusty_tx["new_utxos"] + extra_sponsors,
            version=tx_version,
        )

        return dusty_tx, sweep_tx

    def run_test(self):

        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.test_normal_dust()
        self.test_sponsor_cycle()
        self.test_node_restart()
        self.test_fee_having_parent()
        self.test_multidust()
        self.test_nonzero_dust()
        self.test_non_truc()
        self.test_unspent_ephemeral()
        self.test_reorgs()
        self.test_no_minrelay_fee()

    def test_normal_dust(self):
        self.log.info("Create 0-value dusty output, show that it works inside truc when spent in package")

        assert_equal(self.nodes[0].getrawmempool(), [])
        dusty_tx, sweep_tx = self.create_ephemeral_dust_package(tx_version=3, dust_tx_fee=1000)

        # The parent pays the consensus rate. It is still rejected alone because of the dust output.
        test_res = self.nodes[0].testmempoolaccept([dusty_tx["hex"], sweep_tx["hex"]])
        assert not test_res[0]["allowed"]
        assert_equal(test_res[0]["reject-reason"], "dust")

        # And doesn't work on its own
        assert_raises_rpc_error(-26, "dust", self.nodes[0].sendrawtransaction, dusty_tx["hex"])

        # If we add modified fees, it is still not allowed due to dust check
        self.nodes[0].prioritisetransaction(txid=dusty_tx["txid"], fee_delta=COIN)
        test_res = self.nodes[0].testmempoolaccept([dusty_tx["hex"]])
        assert not test_res[0]["allowed"]
        assert_equal(test_res[0]["reject-reason"], "dust")
        # Reset priority
        self.nodes[0].prioritisetransaction(txid=dusty_tx["txid"], fee_delta=-COIN)
        assert_equal(self.nodes[0].getprioritisedtransactions(), {})

        # A non-zero fee never rescues the dust output, in a package or alone.
        res = self.nodes[0].submitpackage([dusty_tx["hex"], sweep_tx["hex"]])
        assert res["package_msg"] != "success"
        assert "dust" in res["tx-results"][dusty_tx["wtxid"]]["error"]
        assert_equal(self.nodes[0].getrawmempool(), [])

        # A 0-fee parent is a consensus failure. The child does not waive it.
        zero_parent, zero_sweep = self.create_ephemeral_dust_package(tx_version=3, dust_tx_fee=0)
        res = self.nodes[0].submitpackage([zero_parent["hex"], zero_sweep["hex"]])
        assert res["package_msg"] != "success"
        assert "bad-txns-min-fee" in res["tx-results"][zero_parent["wtxid"]]["error"]
        assert_equal(self.nodes[0].getrawmempool(), [])

    def test_node_restart(self):
        self.log.info("Test that an ephemeral package is rejected on restart due to individual evaluation")

        assert_equal(self.nodes[0].getrawmempool(), [])
        dusty_tx, sweep_tx = self.create_ephemeral_dust_package(tx_version=3)

        res = self.nodes[0].submitpackage([dusty_tx["hex"], sweep_tx["hex"]])
        assert res["package_msg"] != "success"
        assert "bad-txns-min-fee" in res["tx-results"][dusty_tx["wtxid"]]["error"]
        assert_mempool_contents(self, self.nodes[0], expected=[])

        self.restart_node(0)
        self.restart_node(1)
        self.connect_nodes(0, 1)
        assert_mempool_contents(self, self.nodes[0], expected=[])

    def test_fee_having_parent(self):
        self.log.info("Test that a transaction with ephemeral dust may not have non-0 base fee")

        assert_equal(self.nodes[0].getrawmempool(), [])

        sats_fee = 1
        dusty_tx, sweep_tx = self.create_ephemeral_dust_package(tx_version=3, dust_tx_fee=sats_fee)
        assert_equal(int(COIN * dusty_tx["fee"]), sats_fee) # has fees
        assert_greater_than(dusty_tx["tx"].vout[0].nValue, 330) # main output is not dust
        assert_equal(dusty_tx["tx"].vout[1].nValue, 0) # added one is dust

        # When base fee is non-0, we report dust like usual
        res = self.nodes[0].submitpackage([dusty_tx["hex"], sweep_tx["hex"]])
        assert_equal(res["package_msg"], "transaction failed")
        assert_equal(res["tx-results"][dusty_tx["wtxid"]]["error"], "dust, tx with dust output must be 0-fee")

        # Priority is ignored: rejected even if modified fee is 0
        self.nodes[0].prioritisetransaction(txid=dusty_tx["txid"], fee_delta=-sats_fee)
        self.nodes[1].prioritisetransaction(txid=dusty_tx["txid"], fee_delta=-sats_fee)
        res = self.nodes[0].submitpackage([dusty_tx["hex"], sweep_tx["hex"]])
        assert_equal(res["package_msg"], "transaction failed")
        assert_equal(res["tx-results"][dusty_tx["wtxid"]]["error"], "dust, tx with dust output must be 0-fee")

        # Will not be accepted if base fee is 0 with modified fee of non-0
        dusty_tx, sweep_tx = self.create_ephemeral_dust_package(tx_version=3)

        self.nodes[0].prioritisetransaction(txid=dusty_tx["txid"], fee_delta=1000)
        self.nodes[1].prioritisetransaction(txid=dusty_tx["txid"], fee_delta=1000)

        # It's rejected submitted alone
        test_res = self.nodes[0].testmempoolaccept([dusty_tx["hex"]])
        assert not test_res[0]["allowed"]
        assert_equal(test_res[0]["reject-reason"], "dust")

        # Or as a package
        res = self.nodes[0].submitpackage([dusty_tx["hex"], sweep_tx["hex"]])
        assert_equal(res["package_msg"], "transaction failed")
        assert_equal(res["tx-results"][dusty_tx["wtxid"]]["error"], "dust, tx with dust output must be 0-fee")

        assert_mempool_contents(self, self.nodes[0], expected=[])

    def test_multidust(self):
        self.log.info("Test that a transaction with multiple ephemeral dusts is not allowed")

        assert_mempool_contents(self, self.nodes[0], expected=[])
        dusty_tx, sweep_tx = self.create_ephemeral_dust_package(tx_version=3, num_dust_outputs=2)

        res = self.nodes[0].submitpackage([dusty_tx["hex"], sweep_tx["hex"]])
        assert_equal(res["package_msg"], "transaction failed")
        assert_equal(res["tx-results"][dusty_tx["wtxid"]]["error"], "dust")
        assert_equal(self.nodes[0].getrawmempool(), [])

    def test_nonzero_dust(self):
        self.log.info("A 0-fee output is a consensus failure even when the relay floor is 0")

        self.restart_node(0, extra_args=["-minrelaytxfee=0"])
        self.restart_node(1, extra_args=["-minrelaytxfee=0"])
        self.connect_nodes(0, 1)

        for value in [1, 329, 330]:
            assert_equal(self.nodes[0].getrawmempool(), [])
            dusty_tx, _ = self.create_ephemeral_dust_package(tx_version=3, dust_value=value)
            test_res = self.nodes[0].testmempoolaccept([dusty_tx["hex"]])
            assert not test_res[0]["allowed"]
            assert_equal(test_res[0]["reject-reason"], "bad-txns-min-fee")

        self.restart_node(0, extra_args=[])
        self.restart_node(1, extra_args=[])
        self.connect_nodes(0, 1)
        assert_mempool_contents(self, self.nodes[0], expected=[])

    # N.B. If individual minrelay requirement is dropped, this test can be dropped
    def test_non_truc(self):
        self.log.info("Test that v2 dust-having transaction is rejected even if spent, because of min relay requirement")

        assert_equal(self.nodes[0].getrawmempool(), [])
        dusty_tx, sweep_tx = self.create_ephemeral_dust_package(tx_version=2)

        res = self.nodes[0].submitpackage([dusty_tx["hex"], sweep_tx["hex"]])
        assert_equal(res["package_msg"], "transaction failed")
        # Non-TRUC hits the relay floor before the consensus fee. The floor is 3 per vbyte.
        parent_vsize = dusty_tx["tx"].get_vsize()
        assert_equal(res["tx-results"][dusty_tx["wtxid"]]["error"], f"min relay fee not met, 0 < {3 * parent_vsize}")

        assert_equal(self.nodes[0].getrawmempool(), [])


    def test_unspent_ephemeral(self):
        self.log.info("A 0-fee dusty parent fails consensus before spend checks run")

        assert_equal(self.nodes[0].getrawmempool(), [])
        dusty_tx, sweep_tx = self.create_ephemeral_dust_package(tx_version=3, dust_value=329)

        res = self.nodes[0].submitpackage([dusty_tx["hex"], sweep_tx["hex"]])
        assert res["package_msg"] != "success"
        assert "bad-txns-min-fee" in res["tx-results"][dusty_tx["wtxid"]]["error"]
        assert_mempool_contents(self, self.nodes[0], expected=[])

    def test_sponsor_cycle(self):
        self.log.info("A sponsored 0-fee dusty parent fails consensus before it can sit in the mempool")

        assert_equal(self.nodes[0].getrawmempool(), [])
        sponsor_coin = self.wallet.get_utxo()
        dusty_tx, sweep_tx = self.create_ephemeral_dust_package(tx_version=3, extra_sponsors=[sponsor_coin])

        res = self.nodes[0].submitpackage([dusty_tx["hex"], sweep_tx["hex"]])
        assert res["package_msg"] != "success"
        assert "bad-txns-min-fee" in res["tx-results"][dusty_tx["wtxid"]]["error"]
        assert_mempool_contents(self, self.nodes[0], expected=[])

    def test_reorgs(self):
        self.log.info("A 0-fee dusty transaction is not a valid block")

        assert_equal(self.nodes[0].getrawmempool(), [])
        self.disconnect_nodes(0, 1)

        dusty_tx, _ = self.create_ephemeral_dust_package(tx_version=3)
        assert_raises_rpc_error(-26, "bad-txns-min-fee", self.nodes[0].sendrawtransaction, dusty_tx["hex"])
        assert_raises_rpc_error(-25, "bad-txns-min-fee", self.nodes[0].generateblock, self.wallet.get_address(), [dusty_tx["hex"]], called_by_framework=True)

        self.log.info("A dusty transaction that pays the consensus rate can be mined and does not re-enter the mempool")
        paying, _ = self.create_ephemeral_dust_package(tx_version=3, dust_tx_fee=100000)
        block_res = self.generateblock(self.nodes[0], self.wallet.get_address(), [paying["hex"]], sync_fun=self.no_op)
        self.nodes[0].invalidateblock(block_res["hash"])
        assert_equal(self.nodes[0].getrawmempool(), [])

        multi, _ = self.create_ephemeral_dust_package(tx_version=3, num_dust_outputs=2, dust_tx_fee=100000)
        block_res = self.generateblock(self.nodes[0], self.wallet.get_address(), [multi["hex"]], sync_fun=self.no_op)
        self.nodes[0].invalidateblock(block_res["hash"])
        assert_equal(self.nodes[0].getrawmempool(), [])

        self.connect_nodes(0, 1)
        self.sync_all()

    def test_no_minrelay_fee(self):
        self.log.info("Clearing the relay floor does not waive the consensus fee")

        self.restart_node(0, extra_args=["-minrelaytxfee=0"])
        self.restart_node(1, extra_args=["-minrelaytxfee=0"])
        self.connect_nodes(0, 1)

        dusty_tx, sweep_tx = self.create_ephemeral_dust_package(tx_version=2)
        res = self.nodes[0].submitpackage([dusty_tx["hex"], sweep_tx["hex"]])
        assert res["package_msg"] != "success"
        assert "bad-txns-min-fee" in res["tx-results"][dusty_tx["wtxid"]]["error"]
        assert_equal(self.nodes[0].getrawmempool(), [])

        self.restart_node(0, extra_args=[])
        self.restart_node(1, extra_args=[])
        self.connect_nodes(0, 1)
        assert_equal(self.nodes[0].getrawmempool(), [])

if __name__ == "__main__":
    EphemeralDustTest(__file__).main()
