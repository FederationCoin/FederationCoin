#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise always-on header v2 / Blake2b PoW on regtest."""

import json
from pathlib import Path

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    CBlockHeader,
    blake2b_header_hash_components,
    from_hex,
    powhash,
    uint256_from_compact,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

V2_HEADER_KEYS = (
    "header_version",
    "nonce2",
    "nonce3",
    "extranonce",
    "time_offset",
    "header_flags",
    "xor_key_mask_clear_bits",
    "xor_key",
    "mm_rhs",
)


class PowChangeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[]]

    def get_header(self, blockhash):
        return from_hex(CBlockHeader(), self.nodes[0].getblockheader(blockhash, False))

    def test_header_vectors(self):
        vectors_path = Path(self.config["environment"]["SRCDIR"]) / "src/test/data/block_header_v2.json"
        with vectors_path.open(encoding="utf8") as vectors_file:
            vectors = json.load(vectors_file)["headers"]

        for vector in vectors:
            fields = vector["fields"]
            header = CBlockHeader()
            header.m_header_v2 = True
            header.nVersion = fields["nVersion"]
            header.hashPrevBlock = int(fields["hashPrevBlock"], 16)
            header.hashMerkleRoot = int(fields["hashMerkleRoot"], 16)
            header.nTime = fields["nTime"]
            header.nBits = fields["nBits"]
            header.nNonce = fields["nNonce"]
            header.m_nonce2 = fields["m_nonce2"]
            header.m_nonce3 = fields["m_nonce3"]
            header.m_extranonce = int(fields["m_extranonce"], 16)
            header.m_time_offset = fields["m_time_offset"]
            header.m_txcount = fields["m_txcount"]
            header.m_flags = fields["m_flags"]
            header.m_xor_key_mask_clear_bits = fields["m_xor_key_mask_clear_bits"]
            header.m_xor_key = int(fields["m_xor_key"], 16)
            header.m_height = fields["m_height"]
            header.m_mm_rhs = int(fields["m_mm_rhs"], 16)

            assert_equal(len(header.serialize()), 166)
            assert_equal(header.serialize().hex(), vector["serialized"])
            components = blake2b_header_hash_components(header)
            assert_equal(components["asic_profile"], vector["asic_profile"])
            assert_equal(components["asic_input"].hex(), vector["asic_input"])
            for component in ("xor_key_hash", "h1", "h2", "mask"):
                assert_equal(components[component].hex(), vector[component])
            assert_equal(components["hash1"].hex(), vector["blake2b_1"])
            assert_equal(components["hash2"].hex(), vector["blake2b_2"])
            assert_equal(components["result"].hex(), vector["block_hash"])
            assert_equal(powhash(header)[::-1].hex(), vector["block_hash"])

    def run_test(self):
        node = self.nodes[0]
        addr = node.get_deterministic_priv_key().address

        self.test_header_vectors()

        self.log.info("Genesis and every mined block use header v2 / Blake2b")
        genesis = self.get_header(node.getblockhash(0))
        assert genesis.m_header_v2
        assert_equal(len(genesis.serialize()), 166)

        self.log.info("getblocktemplate requires the blake2b client rule")
        assert_raises_rpc_error(
            -8, "Support for 'blake2b' rule requires explicit client support",
            lambda: node.getblocktemplate({"rules": ["segwit"]}),
        )
        template = node.getblocktemplate({"rules": ["segwit", "blake2b"]})
        assert template["version"] & 0x80000000
        assert "!blake2b" in template["rules"]
        assert "!sha256d" in template["rules"]
        assert "!fp8gym" in template["rules"]
        assert "!poseidon2" in template["rules"]
        assert_equal(template.get("work_kind"), "blake2b")
        genesis_version = self.get_header(node.getblockhash(0)).get_complete_version()
        assert_equal(genesis_version & 0x300, 0)

        self.generatetoaddress(node, 2, addr)
        tip_hash = node.getbestblockhash()
        tip_header = self.get_header(tip_hash)
        assert tip_header.m_header_v2
        assert_equal(len(tip_header.serialize()), 166)
        assert_equal(tip_hash, powhash(tip_header)[::-1].hex())
        verbose_tip = node.getblockheader(tip_hash)
        assert_equal(verbose_tip["version"], tip_header.nVersion)
        assert_equal(verbose_tip["versionHex"], f"{tip_header.nVersion:08x}")
        assert_equal(verbose_tip["header_version"], 2)
        for key in V2_HEADER_KEYS:
            assert key in verbose_tip, f"missing {key} in verbose v2 header"

        next_height = node.getblockcount() + 1

        self.log.info("A v1 header is invalid")
        invalid_v1 = create_block(
            int(tip_hash, 16),
            create_coinbase(next_height),
            node.getblockheader(tip_hash)["time"] + 1,
            height=next_height,
            header_v2=False,
        )
        invalid_v1.solve()
        assert_raises_rpc_error(
            -25, "bad-version-blake2b",
            lambda: node.submitheader(hexdata=CBlockHeader(invalid_v1).serialize().hex()),
        )

        self.log.info("The high two flag bits are reserved")
        for high_flag in (0x40, 0x80):
            invalid_flags = create_block(
                int(tip_hash, 16),
                create_coinbase(next_height),
                node.getblockheader(tip_hash)["time"] + 1,
                height=next_height,
                header_v2=True,
            )
            invalid_flags.m_flags |= high_flag
            invalid_flags.solve()
            assert_raises_rpc_error(
                -25, "bad-flags-highbits",
                lambda: node.submitheader(hexdata=CBlockHeader(invalid_flags).serialize().hex()),
            )

        assert_equal(tip_header.m_xor_key, 0)
        tip_header.m_xor_key_mask_clear_bits = 255
        disabled_xor = blake2b_header_hash_components(tip_header)
        assert_equal(disabled_xor["mask"], bytes(32))
        assert_equal(disabled_xor["result"], disabled_xor["hash2"])

        merge_mined_block = create_block(
            int(tip_hash, 16),
            create_coinbase(next_height),
            node.getblockheader(tip_hash)["time"] + 1,
            height=next_height,
            header_v2=True,
        )
        merge_mined_block.m_xor_key = 0x0123456789abcdef0123456789abcdef
        merge_mined_block.m_xor_key_mask_clear_bits = 255
        merge_mined_block.m_mm_rhs = 0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
        merge_mined_block.m_extranonce = 0x00112233445566778899aabbccddeeff
        merge_mined_block.m_nonce2 = 0xdeadbeef
        merge_mined_block.m_nonce3 = 0xfeedface
        merge_mined_block.solve()
        assert_equal(node.submitblock(merge_mined_block.serialize().hex()), None)

        mm_json = node.getblockheader(node.getbestblockhash(), True)
        assert_equal(mm_json["header_version"], 2)
        assert_equal(mm_json["extranonce"], merge_mined_block.m_extranonce.to_bytes(16, "little").hex())
        assert_equal(mm_json["xor_key"], merge_mined_block.m_xor_key.to_bytes(16, "little").hex())
        assert_equal(mm_json["mm_rhs"], merge_mined_block.m_mm_rhs.to_bytes(32, "little").hex())
        assert_equal(mm_json["xor_key_mask_clear_bits"], merge_mined_block.m_xor_key_mask_clear_bits)
        assert_equal(mm_json["header_flags"], merge_mined_block.m_flags)
        assert_equal(mm_json["time_offset"], merge_mined_block.m_time_offset)
        assert_equal(len(mm_json["nonce2"]), 8)
        assert_equal(len(mm_json["nonce3"]), 8)
        assert_equal(mm_json["nonce2"], merge_mined_block.m_nonce2.to_bytes(4, "little").hex())
        assert_equal(mm_json["nonce3"], merge_mined_block.m_nonce3.to_bytes(4, "little").hex())

        after_height = node.getblockcount() + 1
        invalid_txcount = create_block(
            merge_mined_block.sha256,
            create_coinbase(after_height),
            merge_mined_block.nTime + 1,
            height=after_height,
            header_v2=True,
        )
        invalid_txcount.m_txcount += 1
        # solve() would refresh m_txcount to len(vtx). Grind with the lying count.
        invalid_txcount.rehash()
        target = uint256_from_compact(invalid_txcount.nBits)
        while invalid_txcount.sha256 > target:
            invalid_txcount.nNonce += 1
            invalid_txcount.rehash()
        assert_equal(node.submitblock(invalid_txcount.serialize().hex()), "bad-txnlist-size")

        invalid_height = create_block(
            merge_mined_block.sha256,
            create_coinbase(after_height),
            merge_mined_block.nTime + 1,
            height=after_height,
            header_v2=True,
        )
        invalid_height.m_height += 1
        invalid_height.solve()
        assert_raises_rpc_error(
            -25, "bad-header-height",
            lambda: node.submitheader(hexdata=CBlockHeader(invalid_height).serialize().hex()),
        )

        self.log.info("Regenerating commitments refreshes the transaction count")
        wallet = MiniWallet(node)
        self.generate(wallet, 100)
        transaction = wallet.create_self_transfer()
        generated = self.generateblock(node, wallet.get_address(), [transaction["hex"]])
        generated_block = node.getblock(generated["hash"])
        generated_header = self.get_header(generated["hash"])
        assert_equal(len(generated_block["tx"]), 2)
        assert_equal(generated_header.m_txcount, 2)

        self.log.info("Header-only entries take nTx from the v2 header")
        header_only_height = node.getblockcount() + 1
        v2_header_only = create_block(
            int(node.getbestblockhash(), 16),
            create_coinbase(header_only_height),
            node.getblockheader(node.getbestblockhash())["time"] + 2,
            height=header_only_height,
            header_v2=True,
        )
        v2_header_only.m_txcount = 3
        v2_header_only.rehash()
        header_target = uint256_from_compact(v2_header_only.nBits)
        while v2_header_only.sha256 > header_target:
            v2_header_only.nNonce += 1
            v2_header_only.rehash()
        assert_equal(node.submitheader(hexdata=CBlockHeader(v2_header_only).serialize().hex()), None)
        v2_header_only_json = node.getblockheader(v2_header_only.hash, True)
        assert_equal(v2_header_only_json["header_version"], 2)
        assert_equal(v2_header_only_json["nTx"], 0)
        assert_equal(v2_header_only_json["txcount"], 3)

        assert_equal(node.getblockheader(tip_hash, True)["nTx"], 1)


if __name__ == "__main__":
    PowChangeTest(__file__).main()
