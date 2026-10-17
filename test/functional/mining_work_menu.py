#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Work-menu kinds: shared S, mixed-kind retarget, submit each kind."""

from test_framework.messages import (
    BLOCK_HEADER_FLAG_USE_TIME_OFFSET,
    CBlock,
    block_identity,
    from_hex,
    powhash,
    work_digest,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

KINDS = ("blake2b", "sha256d", "fp8gym", "poseidon2")
# Gym is a 256×256 MMA plus 2048 Blake2b expands per try. A handful of
# generates is enough; do not grind.
GYM_TRIES = 8
CHEAP_TRIES = 100_000


class MiningWorkMenuTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-con_noretarg=0"]]
        # HTTP timeout is rpc_timeout/2. One gym generate is a single MMA.
        self.rpc_timeout = 120

    def gbt(self, kind="blake2b"):
        return self.nodes[0].getblocktemplate({
            "rules": ["segwit", "blake2b"],
            "work_kind": kind,
        })

    def mine(self, n, kind="blake2b"):
        addr = self.nodes[0].get_deterministic_priv_key().address
        tries = GYM_TRIES if kind == "fp8gym" else CHEAP_TRIES
        return self.generatetoaddress(self.nodes[0], n, addr, tries, kind)

    def nbits_of(self, height):
        h = self.nodes[0].getblockhash(height)
        return int(self.nodes[0].getblockheader(h)["bits"], 16)

    def run_test(self):
        node = self.nodes[0]
        genesis_time = node.getblockheader(node.getblockhash(0))["time"]
        t = genesis_time

        def step_time(delta=1):
            nonlocal t
            t += delta
            node.setmocktime(t)

        self.log.info("GBT advertises the four kinds; default generate is Blake2b")
        tmpl = self.gbt("blake2b")
        for rule in ("!blake2b", "!sha256d", "!fp8gym", "!poseidon2"):
            assert rule in tmpl["rules"]
        assert_equal(tmpl["work_kind"], "blake2b")
        assert "work_kind" in tmpl["capabilities"]
        for kind in KINDS:
            assert_equal(self.gbt(kind)["work_kind"], kind)
        gym_s1 = int(self.gbt("fp8gym")["bits"], 16)

        step_time()
        blake_hash = self.mine(1, "blake2b")[0]
        header = from_hex(CBlock(), node.getblock(blake_hash, 0))
        assert_equal((header.get_complete_version() >> 8) & 3, 0)
        assert_equal(blake_hash, powhash(header)[::-1].hex())
        assert_equal(blake_hash, block_identity(header)[::-1].hex())

        self.log.info("Mine one valid block of each remaining kind")
        kind_hashes = {"blake2b": blake_hash}
        for kind in ("sha256d", "fp8gym", "poseidon2"):
            step_time()
            kind_hashes[kind] = self.mine(1, kind)[0]
            hdr = from_hex(CBlock(), node.getblock(kind_hashes[kind], 0))
            tag = (hdr.get_complete_version() >> 8) & 3
            assert_equal(tag, KINDS.index(kind))
            assert_equal(kind_hashes[kind], block_identity(hdr)[::-1].hex())
            if kind == "sha256d":
                assert_equal(work_digest(hdr), block_identity(hdr))
            else:
                assert powhash(hdr)[::-1].hex() != block_identity(hdr)[::-1].hex()

        self.log.info("Invalid: retag after grind, SHA-256d xor, Poseidon2 time-offset flag")
        sha_hex = node.getblock(kind_hashes["sha256d"], 0)
        retagged = from_hex(CBlock(), sha_hex)
        # Tag Poseidon2 but keep SHA-256d canonical tail; flags stay 0 so Poseidon2
        # TailRule holds. Easy targets may still hit; force a TailRule miss instead
        # by setting SHA-256d-forbidden xor on a SHA-256d-tagged copy, and retag
        # a SHA-256d solution onto Blake2b only after adding a reserved version bit.
        retagged.nVersion = (retagged.nVersion & ~0x300) | (3 << 8)
        retagged.m_flags = 1
        assert_equal(node.submitblock(retagged.serialize().hex()), "high-hash")

        xor_block = from_hex(CBlock(), sha_hex)
        xor_block.m_xor_key = 1
        assert_equal(node.submitblock(xor_block.serialize().hex()), "high-hash")

        p2_hex = node.getblock(kind_hashes["poseidon2"], 0)
        flagged = from_hex(CBlock(), p2_hex)
        flagged.m_flags |= BLOCK_HEADER_FLAG_USE_TIME_OFFSET
        flagged.m_time_offset = 1
        assert_equal(node.submitblock(flagged.serialize().hex()), "high-hash")

        self.log.info("120 blake2b fast window increases S for every kind")
        while node.getblockcount() < 120:
            step_time(1)
            self.mine(1, "blake2b")
        assert_equal(node.getblockcount(), 120)
        genesis_nbits = self.nbits_of(0)
        nbits_s4 = {}
        for kind in KINDS:
            nbits_s4[kind] = int(self.gbt(kind)["bits"], 16)
            assert nbits_s4[kind] != genesis_nbits
            if kind == "fp8gym":
                assert nbits_s4[kind] != gym_s1
        self.log.info("Mine cheap kinds at the new target; gym nBits tracks shared S")
        # Window 120–239 must be slow enough that span >= 4*expected (119
        # gaps). 4*spacing * 119 is just under 4*expected; add a minute.
        spacing = 12 * 60
        slow_delta = 4 * spacing + 60
        for kind in ("blake2b", "sha256d", "poseidon2"):
            step_time(slow_delta)
            mined = self.mine(1, kind)[0]
            hdr = from_hex(CBlock(), node.getblock(mined, 0))
            assert_equal((hdr.get_complete_version() >> 8) & 3, KINDS.index(kind))
            assert_equal(hdr.nBits, nbits_s4[kind])
        assert_equal(int(self.gbt("fp8gym")["bits"], 16), nbits_s4["fp8gym"])

        self.log.info("Heights 159–161: subsidy epoch, S unchanged")
        while node.getblockcount() < 161:
            step_time(slow_delta)
            self.mine(1, "blake2b")
        bits_159 = self.nbits_of(159)
        bits_160 = self.nbits_of(160)
        bits_161 = self.nbits_of(161)
        assert_equal(bits_159, bits_160)
        assert_equal(bits_160, bits_161)
        assert_equal(bits_160, nbits_s4["blake2b"])

        self.log.info("Slow window 120–240 divides S back")
        while node.getblockcount() < 240:
            step_time(slow_delta)
            self.mine(1, "blake2b")
        nbits_after_slow = int(self.gbt("blake2b")["bits"], 16)
        assert_equal(nbits_after_slow, genesis_nbits)
        for kind in ("blake2b", "sha256d", "poseidon2"):
            step_time(spacing)
            self.mine(1, kind)
        assert_equal(int(self.gbt("fp8gym")["bits"], 16), gym_s1)


if __name__ == "__main__":
    MiningWorkMenuTest(__file__).main()
