#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the wallet receives and spends Dilithium 87, Dilithium 44, and secp.

There are 3 nodes-under-test plus a miner:
    - node0 uses Dilithium 87 (default)
    - node1 uses Dilithium 44
    - node2 uses secp
    - node3 mines
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class AddressTypeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.keep_epic21_address_types = True
        self.setup_clean_chain = True
        self.num_nodes = 4
        self.extra_args = [
            ["-addresstype=mldsa87"],
            ["-addresstype=mldsa44"],
            ["-addresstype=secp"],
            [],
        ]
        self.noban_tx_relay = True
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def program_len(self, address):
        info = self.nodes[0].validateaddress(address)
        assert info["isvalid"]
        return len(info["witness_program"]) // 2

    def test_address(self, node, address, typ):
        info = self.nodes[node].getaddressinfo(address)
        assert self.nodes[node].validateaddress(address)["isvalid"]
        assert_equal(info.get("iswitness"), True)
        assert_equal(info["witness_version"], 0)
        prog = info["witness_program"]
        if typ == "secp":
            assert_equal(len(prog), 40)
        else:
            assert_equal(len(prog), 64)
        desc = info.get("desc", "")
        if typ == "mldsa87":
            assert desc.startswith("mldsa87(")
        elif typ == "mldsa44":
            assert desc.startswith("mldsa(")
        elif typ == "secp":
            assert desc.startswith("wpkh(")
        else:
            assert False

    def run_test(self):
        miner = self.nodes[3]
        self.generatetoaddress(miner, COINBASE_MATURITY + 1, miner.getnewaddress())

        self.log.info("Default getnewaddress is Dilithium 87")
        default_addr = self.nodes[0].getnewaddress()
        self.test_address(0, default_addr, "mldsa87")
        assert_equal(self.program_len(default_addr), 32)

        self.log.info("Explicit mldsa44 and secp succeed; heritage types are rejected")
        addr44 = self.nodes[0].getnewaddress("", "mldsa44")
        self.test_address(0, addr44, "mldsa44")
        addr_secp = self.nodes[0].getnewaddress("", "secp")
        self.test_address(0, addr_secp, "secp")
        alias = self.nodes[0].getnewaddress("", "bech32")
        self.test_address(0, alias, "secp")
        for bad in ("legacy", "p2sh-segwit", "bech32m"):
            assert_raises_rpc_error(-5, "Unknown address type", self.nodes[0].getnewaddress, "", bad)
            assert_raises_rpc_error(-5, "Unknown address type", self.nodes[0].getrawchangeaddress, bad)

        self.log.info("New wallets expose only the three product descriptors")
        descs = [d["desc"] for d in self.nodes[0].listdescriptors()["descriptors"]]
        assert any(d.startswith("mldsa87(") for d in descs)
        assert any(d.startswith("mldsa(") for d in descs)
        assert any(d.startswith("wpkh(") for d in descs)
        assert not any(d.startswith("pkh(") for d in descs)
        assert not any(d.startswith("sh(") for d in descs)
        assert not any(d.startswith("tr(") for d in descs)

        self.log.info("Fund the three nodes")
        for i in range(3):
            miner.sendtoaddress(self.nodes[i].getnewaddress(), 10)
        self.generate(miner, 1)
        for i in range(3):
            assert_greater_than(self.nodes[i].getbalance(), 9)

        self.log.info("Send among Dilithium 87, Dilithium 44, and secp and spend the result")
        types = ["mldsa87", "mldsa44", "secp"]
        for from_node, from_typ in enumerate(types):
            for to_node, to_typ in enumerate(types):
                dest = self.nodes[to_node].getnewaddress("", to_typ)
                self.test_address(to_node, dest, to_typ)
                txid = self.nodes[from_node].sendtoaddress(dest, 0.25)
                assert txid
        self.sync_all()
        self.generate(miner, 1)

        for i, typ in enumerate(types):
            change = self.nodes[i].getrawchangeaddress()
            self.test_address(i, change, typ)
            bounce = self.nodes[i].getnewaddress("", typ)
            self.nodes[i].sendtoaddress(bounce, 0.1)
        self.sync_all()
        self.generate(miner, 1)
        for i in range(3):
            assert_greater_than(self.nodes[i].getbalance(), 8)

        self.log.info("Change follows -addresstype")
        dest = self.nodes[2].getnewaddress("", "secp")
        txid = self.nodes[0].sendmany(dummy="", amounts={dest: 0.001})
        tx = self.nodes[0].gettransaction(txid=txid, verbose=True)["decoded"]
        change_addrs = [vout["scriptPubKey"]["address"] for vout in tx["vout"] if vout["scriptPubKey"]["address"] != dest]
        assert_equal(len(change_addrs), 1)
        self.test_address(0, change_addrs[0], "mldsa87")

        self.log.info("createwallet is descriptor-only")
        assert_raises_rpc_error(-4, "Legacy wallets are not supported", miner.createwallet, wallet_name="legacy_no", descriptors=False)


if __name__ == '__main__':
    AddressTypeTest(__file__).main()
