#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A limited-functionality wallet, which may replace a real wallet in tests"""

from copy import deepcopy
from decimal import Decimal
from enum import Enum
import hashlib
from typing import (
    Any,
    Optional,
)
from test_framework.address import (
    address_to_scriptpubkey,
    encode_modern_sig_address,
    key_to_p2pkh,
    key_to_p2sh_p2wpkh,
    key_to_p2wpkh,
    output_key_to_p2tr,
    program_to_witness,
    script_to_p2wsh,
)
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.key import (
    ECKey,
    compute_xonly_pubkey,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    from_hex,
    hash256,
)
from test_framework.mldsa import MINIWALLET_SEED, keygen, keygen87, sign, sign87
from test_framework.script import (
    CScript,
    OP_0,
    OP_DROP,
    SIGHASH_ALL,
    SIGHASH_UNIFIED,
    UnifiedSignatureHash,
    hash160,
    taproot_construct,
)
from test_framework.script_util import (
    fingerprint_to_modern_single_script,
    key_to_p2pk_script,
    key_to_p2pkh_script,
    key_to_p2sh_p2wpkh_script,
    key_to_p2wpkh_script,
)
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    get_fee,
)
from test_framework.wallet_util import generate_keypair

DEFAULT_FEE = Decimal("0.0001")
# Consensus MinimumFee: floor(vsize / 12). Matches src/consensus/settlement_fee.h.
MIN_FEE_VSIZE_DIVISOR = 12


def minimum_fee_tokens(vsize):
    """floor(vsize / 12) tokens. Zero when vsize is not positive."""
    if vsize <= 0:
        return 0
    return vsize // MIN_FEE_VSIZE_DIVISOR

class MiniWalletMode(Enum):
    """Determines the transaction type the MiniWallet is creating and spending.

    For most purposes, the default mode ADDRESS_OP_TRUE should be sufficient;
    it simply uses a fixed bech32 P2WSH address whose script is OP_TRUE, i.e.
    following an anyone-can-spend policy. Taproot is not active on this chain.
    However, if the transactions need to be modified by the user (e.g. prepending
    scriptSig for testing opcodes that are activated by a soft-fork), or the txs
    should contain an actual signature, the raw modes RAW_OP_TRUE and RAW_P2PK
    can be useful. In order to avoid mixing of UTXOs between different MiniWallet
    instances, a tag name can be passed to the default mode, to create different
    output scripts. Note that the UTXOs from the pre-generated test chain can
    only be spent if no tag is passed. Summary of modes:

                    |      output       |           |  tx is   | can modify |  needs
         mode       |    description    |  address  | standard | scriptSig  | signing
    ----------------+-------------------+-----------+----------+------------+----------
    ADDRESS_OP_TRUE | ML-DSA-44 default |  bech32   |   yes    |    no      |   yes
    RAW_OP_TRUE     | secp P2WPKH (raw) |  - (raw)  |   yes    |    no      |   yes
    RAW_P2PK        | secp P2WPKH       |  - (raw)  |   yes    |    no      |   yes
    ADDRESS_MLDSA87 | ML-DSA-87         |  bech32   |   yes    |    no      |   yes
    ADDRESS_SECP    | secp P2WPKH       |  bech32   |   yes    |    no      |   yes
    """
    ADDRESS_OP_TRUE = 1
    RAW_OP_TRUE = 2
    RAW_P2PK = 3
    ADDRESS_MLDSA87 = 4
    ADDRESS_SECP = 5


class MiniWallet:
    def __init__(self, test_node, *, mode=MiniWalletMode.ADDRESS_OP_TRUE, tag_name=None):
        self._test_node = test_node
        self._utxos = []
        self._mode = mode
        # Prevouts this wallet can re-sign after a test mutates outputs.
        self._spent_by_prevout = {}

        assert isinstance(mode, MiniWalletMode)
        if mode == MiniWalletMode.RAW_OP_TRUE:
            assert tag_name is None
            self._priv_key = ECKey()
            self._priv_key.set((1).to_bytes(32, 'big'), True)
            pub = self._priv_key.get_pubkey().get_bytes()
            self._scriptPubKey = CScript([OP_0, hash160(pub)])
        elif mode == MiniWalletMode.RAW_P2PK:
            # use simple deterministic private key (k=1)
            assert tag_name is None
            self._priv_key = ECKey()
            self._priv_key.set((1).to_bytes(32, 'big'), True)
            pub_key = self._priv_key.get_pubkey()
            self._scriptPubKey = CScript([OP_0, hash160(pub_key.get_bytes())])
        elif mode == MiniWalletMode.ADDRESS_OP_TRUE:
            seed = MINIWALLET_SEED if tag_name is None else hashlib.sha256(tag_name.encode()).hexdigest()
            self._mldsa = keygen(self._test_node.binary, seed)
            program = bytes.fromhex(self._mldsa["program"])
            self._scriptPubKey = fingerprint_to_modern_single_script(program, 1)
            self._address = encode_modern_sig_address(self._scriptPubKey)
        elif mode == MiniWalletMode.ADDRESS_MLDSA87:
            seed = MINIWALLET_SEED if tag_name is None else hashlib.sha256(tag_name.encode()).hexdigest()
            self._mldsa87 = keygen87(self._test_node.binary, seed)
            program = bytes.fromhex(self._mldsa87["program"])
            self._scriptPubKey = fingerprint_to_modern_single_script(program, 2)
            self._address = encode_modern_sig_address(self._scriptPubKey)
        elif mode == MiniWalletMode.ADDRESS_SECP:
            assert tag_name is None
            self._priv_key = ECKey()
            self._priv_key.set((1).to_bytes(32, 'big'), True)
            pub = self._priv_key.get_pubkey().get_bytes()
            self._scriptPubKey = CScript([OP_0, hash160(pub)])
            self._address = program_to_witness(0, hash160(pub))

        # When the pre-mined test framework chain is used, it contains coinbase
        # outputs to the MiniWallet's default address in blocks 76-100
        # (see method BitcoinTestFramework._initialize_chain())
        # The MiniWallet needs to rescan_utxos() in order to account
        # for those mature UTXOs, so that all txs spend confirmed coins
        self.rescan_utxos()

    def _create_utxo(self, *, txid, vout, value, height, coinbase, confirmations):
        utxo = {"txid": txid, "vout": vout, "value": value, "height": height, "coinbase": coinbase, "confirmations": confirmations}
        self._register_utxo(txid, vout, value)
        return utxo

    def _register_utxo(self, txid, vout, value):
        sat = int(value * COIN) if isinstance(value, Decimal) else int(value)
        self._spent_by_prevout[(txid, vout)] = CTxOut(sat, bytearray(self._scriptPubKey))

    def _register_tx_outputs(self, tx):
        txid = tx.rehash()
        for i, vout in enumerate(tx.vout):
            if bytes(vout.scriptPubKey) == bytes(self._scriptPubKey):
                self._register_utxo(txid, i, vout.nValue)

    def _lookup_prevout(self, vin):
        n = vin.prevout.n
        hx = "%064x" % vin.prevout.hash
        for key in ((hx, n), (bytes.fromhex(hx)[::-1].hex(), n)):
            out = self._spent_by_prevout.get(key)
            if out is not None:
                return out
        return None

    def _spent_for_tx(self, tx):
        spent = []
        for vin in tx.vin:
            out = self._lookup_prevout(vin)
            if out is None:
                return None
            spent.append(out)
        return spent

    def _resign_hex(self, tx_hex):
        if self._mode not in (
            MiniWalletMode.ADDRESS_OP_TRUE,
            MiniWalletMode.ADDRESS_MLDSA87,
            MiniWalletMode.ADDRESS_SECP,
        ):
            return tx_hex
        try:
            tx = from_hex(CTransaction(), tx_hex)
        except Exception:
            return tx_hex
        spent = self._spent_for_tx(tx)
        if spent is None:
            return tx_hex
        self.sign_tx(tx, spent)
        self._register_tx_outputs(tx)
        return tx.serialize().hex()

    def resign(self, tx):
        """Re-sign after a test mutates outputs. Uses registered MiniWallet prevouts."""
        spent = self._spent_for_tx(tx)
        if spent is None:
            return False
        self.sign_tx(tx, spent)
        self._register_tx_outputs(tx)
        return True

    def pay_minimum_fee(self, tx_info):
        """Raise the fee to floor(weight/4 / 12), matching C++ MinimumFee. Resigns in place."""
        def _sync():
            tx_info["txid"] = tx_info["tx"].rehash()
            tx_info["wtxid"] = tx_info["tx"].getwtxid()
            tx_info["hex"] = tx_info["tx"].serialize().hex()
            utxo = tx_info.get("new_utxo")
            if utxo is not None:
                utxo["value"] = Decimal(tx_info["tx"].vout[0].nValue) / COIN
                utxo["txid"] = tx_info["txid"]
                utxo["wtxid"] = tx_info["wtxid"]
            for i, u in enumerate(tx_info.get("new_utxos") or []):
                u["value"] = Decimal(tx_info["tx"].vout[i].nValue) / COIN
                u["txid"] = tx_info["txid"]
                u["wtxid"] = tx_info["wtxid"]

        while True:
            tx = tx_info["tx"]
            need = minimum_fee_tokens(tx.get_weight() // 4)
            have = int(tx_info["fee"] * COIN)
            extra = need - have
            if extra <= 0:
                return tx_info
            assert tx.vout[0].nValue > extra
            tx.vout[0].nValue -= extra
            assert self.resign(tx)
            tx_info["fee"] += Decimal(extra) / COIN
            _sync()

    def pay_minrelay(self, tx_info, node):
        """Pay at least floor(weight/4 / 12), and the node's minrelay if it is above that."""
        self.pay_minimum_fee(tx_info)
        minrelay = node.getmempoolinfo()["minrelaytxfee"]
        if minrelay <= 0:
            return tx_info
        need = get_fee(tx_info["tx"].get_vsize(), minrelay)
        extra = int((need - tx_info["fee"]) * COIN)
        if extra <= 0:
            return tx_info
        tx = tx_info["tx"]
        assert tx.vout[0].nValue > extra
        tx.vout[0].nValue -= extra
        assert self.resign(tx)
        tx_info["fee"] += Decimal(extra) / COIN
        tx_info["txid"] = tx.rehash()
        tx_info["wtxid"] = tx.getwtxid()
        tx_info["hex"] = tx.serialize().hex()
        utxo = tx_info.get("new_utxo")
        if utxo is not None:
            utxo["value"] = Decimal(tx.vout[0].nValue) / COIN
            utxo["txid"] = tx_info["txid"]
            utxo["wtxid"] = tx_info["wtxid"]
        for i, u in enumerate(tx_info.get("new_utxos") or []):
            u["value"] = Decimal(tx.vout[i].nValue) / COIN
            u["txid"] = tx_info["txid"]
            u["wtxid"] = tx_info["wtxid"]
        return tx_info

    def _bulk_tx(self, tx, target_vsize):
        """Grow one transaction to target_vsize with payment outputs.

        A data script is not a size knob. Tests that need a heavier block add
        transactions instead of calling this.
        """
        if target_vsize <= tx.get_vsize():
            return

        def pay():
            return CTxOut(nValue=0, scriptPubKey=CScript([OP_0, bytes(32)]))

        # Each v0/32 dummy output is 8+1+34 bytes (~43 vB). Do not exceed target.
        need = target_vsize - tx.get_vsize()
        if need > 50:
            n = min(need // 43, 20000)
            tx.vout.extend(pay() for _ in range(n))
            while tx.get_vsize() > target_vsize and tx.vout:
                tx.vout.pop()
        while tx.get_vsize() + 43 <= target_vsize:
            tx.vout.append(pay())
        assert tx.get_vsize() <= target_vsize

    def get_balance(self):
        return sum(u['value'] for u in self._utxos)

    def rescan_utxos(self, *, include_mempool=True):
        """Drop all utxos and rescan the utxo set"""
        self._utxos = []
        res = self._test_node.scantxoutset(action="start", scanobjects=[self.get_descriptor()])
        assert_equal(True, res['success'])
        for utxo in res['unspents']:
            self._utxos.append(
                self._create_utxo(txid=utxo["txid"],
                                  vout=utxo["vout"],
                                  value=utxo["amount"],
                                  height=utxo["height"],
                                  coinbase=utxo["coinbase"],
                                  confirmations=res["height"] - utxo["height"] + 1))
        if include_mempool:
            mempool = self._test_node.getrawmempool(verbose=True)
            # Sort tx by ancestor count. See BlockAssembler::SortForBlock in src/node/miner.cpp
            sorted_mempool = sorted(mempool.items(), key=lambda item: (item[1]["ancestorcount"], int(item[0], 16)))
            for txid, _ in sorted_mempool:
                self.scan_tx(self._test_node.getrawtransaction(txid=txid, verbose=True))

    def scan_tx(self, tx):
        """Scan the tx and adjust the internal list of owned utxos"""
        for spent in tx["vin"]:
            # Mark spent. This may happen when the caller has ownership of a
            # utxo that remained in this wallet. For example, by passing
            # mark_as_spent=False to get_utxo or by using an utxo returned by a
            # create_self_transfer* call.
            try:
                self.get_utxo(txid=spent["txid"], vout=spent["vout"])
            except StopIteration:
                pass
        for out in tx['vout']:
            if out['scriptPubKey']['hex'] == self._scriptPubKey.hex():
                self._utxos.append(self._create_utxo(txid=tx["txid"], vout=out["n"], value=out["value"], height=0, coinbase=False, confirmations=0))

    def scan_txs(self, txs):
        for tx in txs:
            self.scan_tx(tx)

    def sign_tx(self, tx, spent_utxos=None, fixed_length=True):
        if self._mode == MiniWalletMode.ADDRESS_OP_TRUE:
            if spent_utxos is None:
                spent_utxos = self._spent_for_tx(tx)
            assert spent_utxos is not None and len(spent_utxos) == len(tx.vin)
            tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
            hashtype = SIGHASH_ALL | SIGHASH_UNIFIED
            for i in range(len(tx.vin)):
                sighash = UnifiedSignatureHash(b"", tx, i, hashtype, spent_utxos, True)
                assert sighash is not None
                signature = sign(self._test_node.binary, self._mldsa["secret"], sighash)
                tx.wit.vtxinwit[i].scriptWitness.stack = [bytes.fromhex(self._mldsa["pubkey"]), signature]
            tx.rehash()
        elif self._mode == MiniWalletMode.ADDRESS_MLDSA87:
            if spent_utxos is None:
                spent_utxos = self._spent_for_tx(tx)
            assert spent_utxos is not None and len(spent_utxos) == len(tx.vin)
            tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
            hashtype = SIGHASH_ALL | SIGHASH_UNIFIED
            for i in range(len(tx.vin)):
                sighash = UnifiedSignatureHash(b"", tx, i, hashtype, spent_utxos, True)
                assert sighash is not None
                signature = sign87(self._test_node.binary, self._mldsa87["secret"], sighash)
                tx.wit.vtxinwit[i].scriptWitness.stack = [bytes.fromhex(self._mldsa87["pubkey"]), signature]
            tx.rehash()
        elif self._mode in (
            MiniWalletMode.ADDRESS_SECP,
            MiniWalletMode.RAW_OP_TRUE,
            MiniWalletMode.RAW_P2PK,
        ):
            if spent_utxos is None:
                spent_utxos = self._spent_for_tx(tx)
            assert spent_utxos is not None and len(spent_utxos) == len(tx.vin)
            tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
            hashtype = SIGHASH_ALL | SIGHASH_UNIFIED
            pub = self._priv_key.get_pubkey().get_bytes()
            for i in range(len(tx.vin)):
                sighash = UnifiedSignatureHash(b"", tx, i, hashtype, spent_utxos, True)
                assert sighash is not None
                signature = self._priv_key.sign_ecdsa(sighash) + bytes([hashtype])
                tx.wit.vtxinwit[i].scriptWitness.stack = [signature, pub]
            tx.rehash()
        else:
            assert False

    def generate(self, num_blocks, **kwargs):
        """Generate blocks with coinbase outputs to the internal address, and call rescan_utxos"""
        blocks = self._test_node.generatetodescriptor(num_blocks, self.get_descriptor(), **kwargs)
        # Calling rescan_utxos here makes sure that after a generate the utxo
        # set is in a clean state. For example, the wallet will update
        # - if the caller consumed utxos, but never used them
        # - if the caller sent a transaction that is not mined or got rbf'd
        # - after block re-orgs
        # - the utxo height for mined mempool txs
        # - However, the wallet will not consider remaining mempool txs
        self.rescan_utxos()
        return blocks

    def get_output_script(self):
        return self._scriptPubKey

    def get_descriptor(self):
        return descsum_create(f'raw({self._scriptPubKey.hex()})')

    def get_address(self):
        assert self._mode in (
            MiniWalletMode.ADDRESS_OP_TRUE,
            MiniWalletMode.ADDRESS_MLDSA87,
            MiniWalletMode.ADDRESS_SECP,
        )
        return self._address

    def get_utxo(self, *, txid: str = '', vout: Optional[int] = None, mark_as_spent=True, confirmed_only=False) -> dict:
        """
        Returns a utxo and marks it as spent (pops it from the internal list)

        Args:
        txid: get the first utxo we find from a specific transaction
        """
        self._utxos = sorted(self._utxos, key=lambda k: (k['value'], -k['height']))  # Put the largest utxo last
        blocks_height = self._test_node.getblockchaininfo()['blocks']
        mature_coins = list(filter(lambda utxo: not utxo['coinbase'] or COINBASE_MATURITY - 1 <= blocks_height - utxo['height'], self._utxos))
        if txid:
            utxo_filter: Any = filter(lambda utxo: txid == utxo['txid'], self._utxos)
        else:
            utxo_filter = reversed(mature_coins)  # By default the largest utxo
        if vout is not None:
            utxo_filter = filter(lambda utxo: vout == utxo['vout'], utxo_filter)
        if confirmed_only:
            utxo_filter = filter(lambda utxo: utxo['confirmations'] > 0, utxo_filter)
        index = self._utxos.index(next(utxo_filter))
        if mark_as_spent:
            return self._utxos.pop(index)
        else:
            return self._utxos[index]

    def get_utxos(self, *, include_immature_coinbase=False, mark_as_spent=True, confirmed_only=False):
        """Returns the list of all utxos and optionally mark them as spent"""
        if not include_immature_coinbase:
            blocks_height = self._test_node.getblockchaininfo()['blocks']
            utxo_filter = filter(lambda utxo: not utxo['coinbase'] or COINBASE_MATURITY - 1 <= blocks_height - utxo['height'], self._utxos)
        else:
            utxo_filter = self._utxos
        if confirmed_only:
            utxo_filter = filter(lambda utxo: utxo['confirmations'] > 0, utxo_filter)
        utxos = deepcopy(list(utxo_filter))
        if mark_as_spent:
            self._utxos = []
        return utxos

    def send_self_transfer(self, *, from_node, **kwargs):
        """Call create_self_transfer and send the transaction."""
        tx = self.create_self_transfer(**kwargs)
        self.sendrawtransaction(from_node=from_node, tx_hex=tx['hex'])
        return tx

    def send_to(self, *, from_node, scriptPubKey, amount, fee=1000):
        """
        Create and send a tx with an output to a given scriptPubKey/amount,
        plus a change output to our internal address. To keep things simple, a
        fixed fee given in Satoshi is used.

        Note that this method fails if there is no single internal utxo
        available that can cover the cost for the amount and the fixed fee
        (the utxo with the largest value is taken).
        """
        tx = self.create_self_transfer(fee_rate=0)["tx"]
        assert_greater_than_or_equal(tx.vout[0].nValue, amount + fee)
        tx.vout[0].nValue -= (amount + fee)           # change output -> MiniWallet
        tx.vout.append(CTxOut(amount, scriptPubKey))  # arbitrary output -> to be returned
        # Consensus floor is floor(vsize / 12).
        need = max(fee, tx.get_vsize() // 12)
        extra = need - fee
        if extra > 0:
            assert_greater_than_or_equal(tx.vout[0].nValue, extra)
            tx.vout[0].nValue -= extra
            fee = need
        spent_value = sum(out.nValue for out in tx.vout) + fee
        self.sign_tx(tx, [CTxOut(spent_value, bytearray(self._scriptPubKey))])
        txid = self.sendrawtransaction(from_node=from_node, tx_hex=tx.serialize().hex())
        return {
            "sent_vout": 1,
            "txid": txid,
            "wtxid": tx.getwtxid(),
            "hex": tx.serialize().hex(),
            "tx": tx,
        }

    def send_self_transfer_multi(self, *, from_node, **kwargs):
        """Call create_self_transfer_multi and send the transaction."""
        tx = self.create_self_transfer_multi(**kwargs)
        self.sendrawtransaction(from_node=from_node, tx_hex=tx["hex"])
        return tx

    def create_self_transfer_multi(
        self,
        *,
        utxos_to_spend: Optional[list[dict]] = None,
        num_outputs=1,
        amount_per_output=0,
        version=2,
        locktime=0,
        sequence=0,
        fee_per_output=50_000,
        target_vsize=0,
        confirmed_only=False,
    ):
        """
        Create and return a transaction that spends the given UTXOs and creates a
        certain number of outputs with equal amounts. The output amounts can be
        set by amount_per_output or automatically calculated with a fee_per_output.
        """
        utxos_to_spend = utxos_to_spend or [self.get_utxo(confirmed_only=confirmed_only)]
        sequence = [sequence] * len(utxos_to_spend) if type(sequence) is int else sequence
        assert_equal(len(utxos_to_spend), len(sequence))

        # calculate output amount
        inputs_value_total = sum([int(COIN * utxo['value']) for utxo in utxos_to_spend])
        outputs_value_total = inputs_value_total - fee_per_output * num_outputs
        amount_per_output = amount_per_output or (outputs_value_total // num_outputs)
        assert amount_per_output > 0
        outputs_value_total = amount_per_output * num_outputs
        fee = Decimal(inputs_value_total - outputs_value_total) / COIN

        # create tx
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo_to_spend['txid'], 16), utxo_to_spend['vout']), nSequence=seq) for utxo_to_spend, seq in zip(utxos_to_spend, sequence)]
        tx.vout = [CTxOut(amount_per_output, bytearray(self._scriptPubKey)) for _ in range(num_outputs)]
        tx.version = version
        tx.nLockTime = locktime

        spent = [CTxOut(int(COIN * utxo["value"]), bytearray(self._scriptPubKey)) for utxo in utxos_to_spend]
        for utxo in utxos_to_spend:
            self._register_utxo(utxo["txid"], utxo["vout"], utxo["value"])
        self.sign_tx(tx, spent)
        if target_vsize:
            self._bulk_tx(tx, target_vsize)
            self.sign_tx(tx, spent)
        txid = tx.rehash()
        return {
            "new_utxos": [self._create_utxo(
                txid=txid,
                vout=i,
                value=Decimal(tx.vout[i].nValue) / COIN,
                height=0,
                coinbase=False,
                confirmations=0,
            ) for i in range(len(tx.vout))],
            "fee": fee,
            "txid": txid,
            "wtxid": tx.getwtxid(),
            "hex": tx.serialize().hex(),
            "tx": tx,
        }

    def create_self_transfer(
            self,
            *,
            fee_rate=Decimal("0.003"),
            fee=Decimal("0"),
            utxo_to_spend=None,
            target_vsize=0,
            confirmed_only=False,
            **kwargs,
    ):
        """Create and return a tx with the specified fee. If fee is 0, use fee_rate, where the resulting fee may be exact or at most one satoshi higher than needed."""
        utxo_to_spend = utxo_to_spend or self.get_utxo(confirmed_only=confirmed_only)
        assert fee_rate >= 0
        assert fee >= 0
        # calculate fee
        if self._mode == MiniWalletMode.ADDRESS_OP_TRUE:
            vsize = Decimal(1100)  # one ML-DSA-44 key and signature, witness-discounted
        elif self._mode == MiniWalletMode.ADDRESS_MLDSA87:
            vsize = Decimal(2000)  # one ML-DSA-87 key and signature, witness-discounted
        elif self._mode in (
            MiniWalletMode.ADDRESS_SECP,
            MiniWalletMode.RAW_OP_TRUE,
            MiniWalletMode.RAW_P2PK,
        ):
            vsize = Decimal(140)
        else:
            assert False
        if target_vsize and not fee:  # respect fee_rate if target vsize is passed
            fee = get_fee(target_vsize, fee_rate)
            if fee_rate > 0:
                floor = Decimal(minimum_fee_tokens(target_vsize)) / COIN
                if fee < floor:
                    fee = floor
        if fee:
            paid = fee
        elif fee_rate > 0:
            paid = max(fee_rate * vsize / 1000, Decimal(minimum_fee_tokens(int(vsize))) / COIN)
        else:
            paid = Decimal(0)
        send_value = utxo_to_spend["value"] - paid
        if send_value <= 0:
            raise RuntimeError(f"UTXO value {utxo_to_spend['value']} is too small to cover fees {paid}")
        # create tx
        tx = self.create_self_transfer_multi(
            utxos_to_spend=[utxo_to_spend],
            amount_per_output=int(COIN * send_value),
            target_vsize=target_vsize,
            **kwargs,
        )
        # A P2WSH spend is not one fixed size. Measure once and rebuild so the fee matches the feerate.
        if not target_vsize and not fee:
            actual = tx["tx"].get_vsize()
            if fee_rate > 0:
                paid = max(fee_rate * Decimal(actual) / 1000, Decimal(minimum_fee_tokens(actual)) / COIN)
            else:
                paid = Decimal(0)
            new_send = utxo_to_spend["value"] - paid
            if int(COIN * new_send) != tx["tx"].vout[0].nValue:
                tx = self.create_self_transfer_multi(
                    utxos_to_spend=[utxo_to_spend],
                    amount_per_output=int(COIN * new_send),
                    **kwargs,
                )
        tx["new_utxo"] = tx.pop("new_utxos")[0]

        return tx

    def sendrawtransaction(self, *, from_node, tx_hex, maxfeerate=0, **kwargs):
        tx_hex = self._resign_hex(tx_hex)
        txid = from_node.sendrawtransaction(hexstring=tx_hex, maxfeerate=maxfeerate, **kwargs)
        self.scan_tx(from_node.decoderawtransaction(tx_hex))
        return txid

    def create_self_transfer_chain(self, *, chain_length, utxo_to_spend=None):
        """
        Create a "chain" of chain_length transactions. The nth transaction in
        the chain is a child of the n-1th transaction and parent of the n+1th transaction.
        """
        chaintip_utxo = utxo_to_spend or self.get_utxo()
        chain = []

        for _ in range(chain_length):
            tx = self.create_self_transfer(utxo_to_spend=chaintip_utxo)
            chaintip_utxo = tx["new_utxo"]
            chain.append(tx)

        return chain

    def send_self_transfer_chain(self, *, from_node, **kwargs):
        """Create and send a "chain" of chain_length transactions. The nth transaction in
        the chain is a child of the n-1th transaction and parent of the n+1th transaction.

        Returns a list of objects for each tx (see create_self_transfer_multi).
        """
        chain = self.create_self_transfer_chain(**kwargs)
        for t in chain:
            self.sendrawtransaction(from_node=from_node, tx_hex=t["hex"])
        return chain


def getnewdestination(address_type='bech32'):
    """Generate a random destination of the specified type and return the
       corresponding public key, scriptPubKey and address. Supported types are
       'legacy', 'p2sh-segwit', 'bech32' and 'bech32m'. Can be used when a random
       destination is needed, but no compiled wallet is available (e.g. as
       replacement to the getnewaddress/getaddressinfo RPCs)."""
    key, pubkey = generate_keypair()
    if address_type == 'legacy':
        scriptpubkey = key_to_p2pkh_script(pubkey)
        address = key_to_p2pkh(pubkey)
    elif address_type == 'p2sh-segwit':
        scriptpubkey = key_to_p2sh_p2wpkh_script(pubkey)
        address = key_to_p2sh_p2wpkh(pubkey)
    elif address_type == 'bech32':
        scriptpubkey = key_to_p2wpkh_script(pubkey)
        address = key_to_p2wpkh(pubkey)
    elif address_type == 'bech32m':
        tap = taproot_construct(compute_xonly_pubkey(key.get_bytes())[0])
        pubkey = tap.output_pubkey
        scriptpubkey = tap.scriptPubKey
        address = output_key_to_p2tr(pubkey)
    else:
        assert False
    return pubkey, scriptpubkey, address
