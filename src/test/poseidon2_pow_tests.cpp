// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/work/kind.h>
#include <consensus/work/poseidon2.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(poseidon2_pow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sbox_and_zero_permute)
{
    BOOST_CHECK_EQUAL(Consensus::GOLDILOCKS_P, 0xFFFFFFFF00000001ULL);
    std::array<uint64_t, Consensus::POSEIDON2_WIDTH> z{};
    Consensus::Poseidon2Permute(z);
    const uint64_t p3_zero[12] = {
        0xc9bc9432e1686884, 0x03ecbab0dcdd2189, 0x5e7ac885b3dc1215, 0x6ac07513801d191f,
        0xca5c593fb184dcfc, 0x414dec5f3e455287, 0x1a17df170127ae41, 0xe7e592bd0af9b0a5,
        0xc71a9b27edc66a4c, 0x2728671759ac43c2, 0xb9969c20f7f672f9, 0xc5140b586823b92f,
    };
    for (unsigned i{0}; i < 12; ++i) {
        BOOST_CHECK_EQUAL(z[i], p3_zero[i]);
    }
}

BOOST_AUTO_TEST_CASE(quantus_hash_bytes_kats)
{
    // Copied from qp-poseidon-core test_known_value_hashes (injective encoding).
    const auto empty{Consensus::Poseidon2HashBytes({})};
    BOOST_CHECK_EQUAL(HexStr(empty), "4d8d22af81f6c27a005a07028590ef4ee480f6c4b93f813daf9de47a07c8ae86");
    const unsigned char zero_byte{0};
    const auto one_zero{Consensus::Poseidon2HashBytes({&zero_byte, 1})};
    BOOST_CHECK_EQUAL(HexStr(one_zero), "8f5b42e350ff5a12788210c86c2bcd49243b8f9350de818b3b0c56839a42ebad");
}

BOOST_AUTO_TEST_CASE(squeeze_twice_first_half_is_hash_bytes)
{
    const unsigned char msg[]{"test 512-bit hash"};
    const auto h64{Consensus::Poseidon2HashSqueezeTwice({msg, sizeof(msg) - 1})};
    const auto h32{Consensus::Poseidon2HashBytes({msg, sizeof(msg) - 1})};
    BOOST_CHECK(std::equal(h32.begin(), h32.end(), h64.begin()));
    BOOST_CHECK_EQUAL(h64.size(), 64U);
}

BOOST_AUTO_TEST_CASE(header_pre_changes_with_merkle_not_nonce)
{
    CBlockHeader header;
    header.m_header_v2 = true;
    header.nVersion = 1;
    Consensus::ApplyWorkKindTag(header, Consensus::WorkKindTag::POSEIDON2);
    header.hashMerkleRoot = uint256::ONE;
    const uint256 pre0{Consensus::Poseidon2Preimage(header)};
    header.nNonce = 42;
    BOOST_CHECK(Consensus::Poseidon2Preimage(header) == pre0);
    header.hashMerkleRoot = uint256::ZERO;
    BOOST_CHECK(Consensus::Poseidon2Preimage(header) != pre0);
}

BOOST_AUTO_TEST_SUITE_END()
