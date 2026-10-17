#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpful routines for mempool testing."""

from decimal import Decimal

from .blocktools import (
    COINBASE_MATURITY,
)
from .messages import (
    COIN,
    CTransaction,
)
from .util import (
    assert_equal,
    assert_greater_than,
    create_lots_of_big_transactions,
    gen_return_txouts,
)
from .wallet import (
    MiniWallet,
    minimum_fee_tokens,
)

ORPHAN_TX_EXPIRE_TIME = 1200
# C++ DEFAULT_MIN_RELAY_TX_FEE. Consensus floor is floor(vsize / 12).
DEFAULT_MIN_RELAY_TX_FEE = 0
# -corepolicy incremental when that flag is on. Tokens per kvB.
DEFAULT_INCREMENTAL_RELAY_FEE = 100
# Historical Core incremental, used if a test turns -corepolicy on.
COREPOLICY_MIN_RELAY_TX_FEE = 100


def relay_feerate_sat_vb_str(node):
    """CFeeRate::ToString(SAT_VB) for the node's min relay feerate."""
    sat_kvb = int(node.getnetworkinfo()["relayfee"] * COIN)
    return f"{sat_kvb // 1000}.{sat_kvb % 1000:03d} token/vB"


def just_below_relay_sat_vb(node):
    """Largest representable token/vB rate strictly below the node's minrelay."""
    sat_kvb = int(node.getnetworkinfo()["relayfee"] * COIN)
    assert sat_kvb > 0
    return Decimal(sat_kvb - 1) / Decimal(1000)


def just_below_relay_sat_vb_str(node):
    sat_kvb = int(node.getnetworkinfo()["relayfee"] * COIN)
    assert sat_kvb > 0
    below = sat_kvb - 1
    return f"{below // 1000}.{below % 1000:03d} token/vB"

def assert_mempool_contents(test_framework, node, expected=None, sync=True):
    """Assert that all transactions in expected are in the mempool,
    and no additional ones exist. 'expected' is an array of
    CTransaction objects
    """
    if sync:
        test_framework.sync_mempools()
    if not expected:
        expected = []
    assert_equal(len(expected), len(set(expected)))
    mempool = node.getrawmempool(verbose=False)
    assert_equal(len(mempool), len(expected))
    for tx in expected:
        assert tx.rehash() in mempool


def fill_mempool(test_framework, node, *, tx_sync_fun=None):
    """Fill mempool until eviction.

    Allows for simpler testing of scenarios with floating mempoolminfee > minrelay
    Requires -maxmempool=5. The filler transactions are payments, and each
    pays at least the node min-relay rate (above floor(vsize / 12)).
    To avoid unintentional tx dependencies, the mempool filling txs are created with a
    tagged ephemeral miniwallet instance.
    """
    test_framework.log.info("Fill the mempool until eviction is triggered and the mempoolminfee rises")
    txouts = gen_return_txouts()
    minrelayfee = node.getnetworkinfo()['relayfee']
    # Filler transactions must pay consensus MinimumFee (floor(vsize / 12)).
    # When minrelay is 0, do not invent a linear token/vB stand-in; the victim
    # pays that floor and later batches pay a multiple of the dummy's floor.
    fill_fee = minrelayfee

    tx_batch_size = 1
    num_of_batches = 75
    # Generate UTXOs to flood the mempool
    # 1 to create a tx initially that will be evicted from the mempool later
    # 75 transactions each with a fee rate higher than the previous one
    ephemeral_miniwallet = MiniWallet(node, tag_name="fill_mempool_ephemeral_wallet")
    test_framework.generate(ephemeral_miniwallet, 1 + num_of_batches * tx_batch_size)

    # Mine enough blocks so that the UTXOs are allowed to be spent
    test_framework.generate(node, COINBASE_MATURITY - 1)

    # Get all UTXOs up front to ensure none of the transactions spend from each other, as that may
    # change their effective feerate and thus the order in which they are selected for eviction.
    confirmed_utxos = [ephemeral_miniwallet.get_utxo(confirmed_only=True) for _ in range(num_of_batches * tx_batch_size + 1)]
    assert_equal(len(confirmed_utxos), num_of_batches * tx_batch_size + 1)

    # Calibrate dummy tx memory usage, since we rely on filling maxmempool
    target_tx_usage = 68064
    tx = ephemeral_miniwallet.create_self_transfer(utxo_to_spend=confirmed_utxos[0])["tx"]
    tx.vout.extend(txouts)
    ephemeral_miniwallet.resign(tx)
    res = node.testmempoolaccept([tx.serialize().hex()])[0]
    if res['usage'] > target_tx_usage:
        excess_outputs = len(txouts) - (target_tx_usage * len(txouts) // res['usage'])
        txouts = txouts[excess_outputs:]

    test_framework.log.debug("Create a mempool tx that will be evicted")
    if fill_fee > 0:
        tx_to_be_evicted_id = ephemeral_miniwallet.send_self_transfer(
            from_node=node, utxo_to_spend=confirmed_utxos.pop(0), fee_rate=fill_fee)["txid"]
        # ~65k vB dummy: feerate * 130 ≈ 2x that feerate as an absolute fee.
        base_fee = fill_fee * 130
    else:
        victim = ephemeral_miniwallet.create_self_transfer(
            utxo_to_spend=confirmed_utxos.pop(0), fee=0, fee_rate=0)
        ephemeral_miniwallet.pay_minimum_fee(victim)
        tx_to_be_evicted_id = ephemeral_miniwallet.sendrawtransaction(
            from_node=node, tx_hex=victim["hex"])
        probe = ephemeral_miniwallet.create_self_transfer(
            utxo_to_spend=confirmed_utxos[0], fee=0, fee_rate=0)
        probe["tx"].vout.extend(txouts)
        ephemeral_miniwallet.resign(probe["tx"])
        dummy_floor = Decimal(minimum_fee_tokens(probe["tx"].get_vsize())) / COIN
        base_fee = dummy_floor * 2

    def send_batch(fee):
        utxos = confirmed_utxos[:tx_batch_size]
        create_lots_of_big_transactions(ephemeral_miniwallet, node, fee, tx_batch_size, txouts, utxos)
        del confirmed_utxos[:tx_batch_size]

    batch_fees = [(i + 1) * base_fee for i in range(num_of_batches)]

    test_framework.log.debug("Fill up the mempool with txs with higher fee rate")
    for fee in batch_fees[:-3]:
        send_batch(fee)
    tx_sync_fun() if tx_sync_fun else test_framework.sync_mempools()  # sync before any eviction
    assert_equal(node.getmempoolinfo()["mempoolminfee"], minrelayfee)
    for fee in batch_fees[-3:]:
        send_batch(fee)
    tx_sync_fun() if tx_sync_fun else test_framework.sync_mempools()  # sync after all evictions

    test_framework.log.debug("The tx should be evicted by now")
    # The number of transactions created should be greater than the ones present in the mempool
    assert_greater_than(tx_batch_size * num_of_batches, len(node.getrawmempool()))
    # Initial tx created should not be present in the mempool anymore as it had a lower fee rate
    assert tx_to_be_evicted_id not in node.getrawmempool()

    test_framework.log.debug("Check that mempoolminfee is larger than minrelaytxfee")
    assert_equal(node.getmempoolinfo()['minrelaytxfee'], minrelayfee)
    assert_greater_than(node.getmempoolinfo()['mempoolminfee'], minrelayfee)

def tx_in_orphanage(node, tx: CTransaction) -> bool:
    """Returns true if the transaction is in the orphanage."""
    found = [o for o in node.getorphantxs(verbosity=1) if o["txid"] == tx.rehash() and o["wtxid"] == tx.getwtxid()]
    return len(found) == 1
