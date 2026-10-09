#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""signrawtransactionwithkey signs a named secp spend and refuses closed layouts."""

from decimal import Decimal

from test_framework.address import address_to_scriptpubkey, p2a
from test_framework.authproxy import JSONRPCException
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet, MiniWalletMode, getnewdestination
from test_framework.wallet_util import bytes_to_wif, generate_keypair


class SignRawTransactionWithKeyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def send_to_script(self, script_pub_key, amount):
        tx = self.funder.send_to(from_node=self.nodes[0], scriptPubKey=script_pub_key, amount=int(amount * COIN))
        return tx["txid"], tx["sent_vout"]

    def run_test(self):
        self.funder = MiniWallet(self.nodes[0])
        self.secp = MiniWallet(self.nodes[0], mode=MiniWalletMode.ADDRESS_SECP)
        self.funder.send_to(from_node=self.nodes[0], scriptPubKey=self.secp.get_output_script(), amount=10 * COIN)
        self.generate(self.nodes[0], 1)
        self.secp.rescan_utxos()
        self.funder.rescan_utxos()
        self.successful_secp_signing()
        self.dilithium_secret_is_not_a_wif()
        self.closed_p2sh_p2wsh()
        self.keyless_signing_test()
        self.invalid_sighashtype_test()
        self.invalid_private_key_and_tx()

    def successful_secp_signing(self):
        self.log.info("signrawtransactionwithkey completes a MiniWallet secp spend")
        utxo = self.secp.get_utxo()
        dest = self.secp.get_address()
        raw = self.nodes[0].createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{dest: utxo["value"] - Decimal("0.0001")}],
        )
        prev = {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "scriptPubKey": self.secp.get_output_script().hex(),
            "amount": utxo["value"],
        }
        wif = bytes_to_wif((1).to_bytes(32, "big"), compressed=True)
        signed = self.nodes[0].signrawtransactionwithkey(raw, [wif], [prev])
        assert "errors" not in signed
        assert_equal(signed["complete"], True)
        self.nodes[0].sendrawtransaction(signed["hex"])
        self.generate(self.nodes[0], 1)

    def dilithium_secret_is_not_a_wif(self):
        self.log.info("signrawtransactionwithkey does not take a Dilithium 44 secret")
        utxo = self.funder.get_utxo()
        raw = self.nodes[0].createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{self.funder.get_address(): utxo["value"] - Decimal("0.0001")}],
        )
        assert_raises_rpc_error(
            -5,
            "Invalid private key",
            self.nodes[0].signrawtransactionwithkey,
            raw,
            [self.funder._mldsa["secret"]],
        )
        wif = bytes_to_wif((1).to_bytes(32, "big"), compressed=True)
        prev = {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "scriptPubKey": self.funder.get_output_script().hex(),
            "amount": utxo["value"],
        }
        assert_raises_rpc_error(
            -8,
            "Missing redeemScript/witnessScript",
            self.nodes[0].signrawtransactionwithkey,
            raw,
            [wif],
            [prev],
        )

    def closed_p2sh_p2wsh(self):
        self.log.info("P2SH and P2WSH destinations stay invalid")
        priv, pubkey = generate_keypair(wif=True)
        dest = getnewdestination()[2]
        for address_type in ("legacy", "p2sh-segwit", "bech32"):
            if address_type in ("legacy", "p2sh-segwit"):
                assert_raises_rpc_error(-5, "Unknown address type", self.nodes[0].createmultisig, 1, [pubkey.hex()], address_type)
                continue
            created = self.nodes[0].createmultisig(1, [pubkey.hex()], address_type)
            script = address_to_scriptpubkey(created["address"])
            try:
                txid, vout = self.send_to_script(script, Decimal("1"))
            except JSONRPCException as exc:
                assert exc.error["message"], exc.error
                continue
            self.generate(self.nodes[0], 1)
            raw = self.nodes[0].createrawtransaction(
                [{"txid": txid, "vout": vout}],
                [{dest: Decimal("0.999")}],
            )
            prev = {
                "txid": txid,
                "vout": vout,
                "scriptPubKey": script.hex(),
                "redeemScript": created["redeemScript"],
                "witnessScript": created["redeemScript"],
                "amount": Decimal("1"),
            }
            signed = self.nodes[0].signrawtransactionwithkey(raw, [priv], [prev])
            hex_tx = signed["hex"] if signed.get("hex") else raw
            result = self.nodes[0].testmempoolaccept([hex_tx])[0]
            assert_equal(result["allowed"], False)

    def keyless_signing_test(self):
        self.log.info("Pay-to-anchor outputs are rejected")
        assert_raises_rpc_error(-26, "bad-txns-vout-taproot-disabled", self.send_to_script, address_to_scriptpubkey(p2a()), Decimal("1"))

    def invalid_sighashtype_test(self):
        self.log.info("Test signing transaction with invalid sighashtype")
        utxo = self.funder.get_utxo(mark_as_spent=False)
        tx = self.nodes[0].createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{self.funder.get_address(): Decimal("0.1")}],
        )
        wif = bytes_to_wif((1).to_bytes(32, "big"), compressed=True)
        assert_raises_rpc_error(-8, "'all' is not a valid sighash parameter.", self.nodes[0].signrawtransactionwithkey, tx, [wif], sighashtype="all")

    def invalid_private_key_and_tx(self):
        self.log.info("Test signing transaction with an invalid private key")
        utxo = self.funder.get_utxo(mark_as_spent=False)
        tx = self.nodes[0].createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{self.funder.get_address(): Decimal("0.1")}],
        )
        assert_raises_rpc_error(-5, "Invalid private key", self.nodes[0].signrawtransactionwithkey, tx, ["123"])
        self.log.info("Test signing transaction with an invalid tx hex")
        wif = bytes_to_wif((1).to_bytes(32, "big"), compressed=True)
        assert_raises_rpc_error(-22, "TX decode failed. Make sure the tx has at least one input.", self.nodes[0].signrawtransactionwithkey, tx + "00", [wif])


if __name__ == "__main__":
    SignRawTransactionWithKeyTest(__file__).main()
