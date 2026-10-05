#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""BIP66 still applies to secp DER on the unified witness spend."""

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode


def pad_s(sig_with_ht):
    """Add a leading 0x00 to S. BIP66 forbids that padding."""
    sig, hashtype = sig_with_ht[:-1], sig_with_ht[-1:]
    assert sig[0] == 0x30
    len_r = sig[3]
    len_s = sig[5 + len_r]
    s_start = 6 + len_r
    body = bytearray(sig[2:s_start])
    body[-1] = len_s + 1
    padded = bytes([0x30, sig[1] + 1]) + bytes(body) + b"\x00" + sig[s_start:]
    return padded + hashtype


class BIP66Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.noban_tx_relay = True
        self.setup_clean_chain = True

    def block_with(self, tx=None, *, version=None):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        txs = [tx] if tx is not None else None
        block = create_block(
            int(tip, 16),
            create_coinbase(height),
            ntime=node.getblockheader(tip)["time"] + 1,
            txlist=txs,
            height=height,
            header_v2=True,
            version=version,
        )
        add_witness_commitment(block)
        block.solve()
        return block

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.ADDRESS_SECP)
        self.generate(wallet, 110)

        assert_equal(
            node.getdeploymentinfo()["deployments"]["bip66"],
            {"active": True, "height": 1, "type": "buried"},
        )

        self.log.info("A canonical secp witness spend is accepted")
        paid = wallet.send_self_transfer(from_node=node)
        self.generate(node, 1)
        assert paid["txid"] not in node.getrawmempool()

        self.log.info("A padded-S secp witness spend is refused")
        tx = wallet.create_self_transfer()["tx"]
        stack = tx.wit.vtxinwit[0].scriptWitness.stack
        stack[0] = pad_s(stack[0])
        tx.rehash()
        result = node.testmempoolaccept(rawtxs=[tx.serialize().hex()])[0]
        assert_equal(result["allowed"], False)
        assert result.get("reject-reason")
        block_result = node.submitblock(self.block_with(tx).serialize().hex())
        assert block_result is not None, "padded-S must not land in a block"

        self.log.info("DERSIG still refuses version-2 blocks")
        block = self.block_with(version=2)
        assert_equal(node.submitblock(block.serialize().hex()), f"bad-version(0x{block.nVersion:08x})")


if __name__ == "__main__":
    BIP66Test(__file__).main()
