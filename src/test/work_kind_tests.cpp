// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/block_header_v2.json.h>

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/work/kind.h>
#include <consensus/work/fp8_gym.h>
#include <consensus/work/poseidon2.h>
#include <hash.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/chaintype.h>

#include <algorithm>
#include <span>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(work_kind_tests, BasicTestingSetup)

static CBlockHeader HeaderFromV2Json(const UniValue& fields)
{
    CBlockHeader header;
    header.m_header_v2 = true;
    header.nVersion = fields["nVersion"].getInt<int32_t>();
    header.hashPrevBlock = *uint256::FromHex(fields["hashPrevBlock"].get_str());
    header.hashMerkleRoot = *uint256::FromHex(fields["hashMerkleRoot"].get_str());
    header.nTime = fields["nTime"].getInt<uint32_t>();
    header.nBits = fields["nBits"].getInt<uint32_t>();
    header.nNonce = fields["nNonce"].getInt<uint32_t>();
    header.m_nonce2 = fields["m_nonce2"].getInt<uint32_t>();
    header.m_nonce3 = fields["m_nonce3"].getInt<uint32_t>();
    const auto extranonce{ParseHex(fields["m_extranonce"].get_str())};
    BOOST_REQUIRE_EQUAL(extranonce.size(), header.m_extranonce.size());
    std::reverse_copy(extranonce.begin(), extranonce.end(), header.m_extranonce.begin());
    header.m_time_offset = fields["m_time_offset"].getInt<uint32_t>();
    header.m_txcount = fields["m_txcount"].getInt<uint16_t>();
    header.m_flags = fields["m_flags"].getInt<uint8_t>();
    header.m_xor_key_mask_clear_bits = fields["m_xor_key_mask_clear_bits"].getInt<uint8_t>();
    const auto xor_key{ParseHex(fields["m_xor_key"].get_str())};
    BOOST_REQUIRE_EQUAL(xor_key.size(), header.m_xor_key.size());
    std::reverse_copy(xor_key.begin(), xor_key.end(), header.m_xor_key.begin());
    header.m_height = fields["m_height"].getInt<int32_t>();
    header.m_mm_rhs = *uint256::FromHex(fields["m_mm_rhs"].get_str());
    return header;
}

BOOST_AUTO_TEST_CASE(tag_decode)
{
    BOOST_CHECK(!Consensus::DecodeWorkKindTag(1));
    const uint32_t v2{CBlockHeader::VERSION_HEADER_V2_FLAG | 1};
    BOOST_CHECK_EQUAL(static_cast<int>(*Consensus::DecodeWorkKindTag(v2)), static_cast<int>(Consensus::WorkKindTag::BLAKE2B));
    // BIP9 testdummy (28) and VERSIONBITS_TOP_BITS (29) stay legal.
    BOOST_CHECK_EQUAL(static_cast<int>(*Consensus::DecodeWorkKindTag(v2 | (1u << 28) | (1u << 29))), static_cast<int>(Consensus::WorkKindTag::BLAKE2B));
    BOOST_CHECK_EQUAL(static_cast<int>(*Consensus::DecodeWorkKindTag(v2 | (1u << 8))), static_cast<int>(Consensus::WorkKindTag::SHA256D));
    BOOST_CHECK_EQUAL(static_cast<int>(*Consensus::DecodeWorkKindTag(v2 | (2u << 8))), static_cast<int>(Consensus::WorkKindTag::FP8_GYM));
    BOOST_CHECK_EQUAL(static_cast<int>(*Consensus::DecodeWorkKindTag(v2 | (3u << 8))), static_cast<int>(Consensus::WorkKindTag::POSEIDON2));
    BOOST_CHECK(!Consensus::DecodeWorkKindTag(v2 | (1u << 10)));
    BOOST_CHECK_EQUAL(static_cast<int>(*Consensus::DecodeWorkKindTag(v2 | (1u << 12) | (1u << 30))), static_cast<int>(Consensus::WorkKindTag::BLAKE2B));
    BOOST_CHECK(Consensus::LookupWorkKind(Consensus::WorkKindTag::BLAKE2B));
    BOOST_CHECK_EQUAL(std::string(Consensus::LookupWorkKind(Consensus::WorkKindTag::SHA256D)->Name()), "sha256d");
}

BOOST_AUTO_TEST_CASE(blake2b_gethash_identical)
{
    UniValue data;
    BOOST_REQUIRE(data.read(json_tests::block_header_v2));
    const Consensus::WorkKind* blake{Consensus::LookupWorkKind(Consensus::WorkKindTag::BLAKE2B)};
    for (const UniValue& test : data["headers"].getValues()) {
        const CBlockHeader header{HeaderFromV2Json(test["fields"])};
        BOOST_CHECK_EQUAL(header.GetHash().GetHex(), test["block_hash"].get_str());
        BOOST_CHECK_EQUAL(blake->WorkDigest(header).GetHex(), test["block_hash"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(apply_tag_does_not_force_bit2_over_top_bits)
{
    CBlockHeader header;
    header.nVersion = 0x20000000; // VERSIONBITS_TOP_BITS
    Consensus::ApplyWorkKindTag(header, Consensus::WorkKindTag::BLAKE2B);
    const uint32_t v{static_cast<uint32_t>(header.nVersion)};
    BOOST_CHECK_EQUAL(v & (1u << 2), 0u);
    BOOST_CHECK_EQUAL(v & 0x20000000u, 0x20000000u);
    BOOST_CHECK_EQUAL((v >> 8) & 3u, 0u);

    header.nVersion = 1;
    Consensus::ApplyWorkKindTag(header, Consensus::WorkKindTag::SHA256D);
    BOOST_CHECK_GE(header.nVersion & 0x7fffffff, 4);
    BOOST_CHECK_EQUAL((static_cast<uint32_t>(header.nVersion) >> 8) & 3u, 1u);
}

BOOST_AUTO_TEST_CASE(sha256d_80_ignores_tail_bytes)
{
    CBlockHeader header;
    header.m_header_v2 = true;
    header.nVersion = 1;
    Consensus::ApplyWorkKindTag(header, Consensus::WorkKindTag::SHA256D);
    header.nBits = 0x207fffff;
    header.nTime = 123;
    header.nNonce = 99;
    const Consensus::WorkKind* sha{Consensus::LookupWorkKind(Consensus::WorkKindTag::SHA256D)};
    const uint256 d0{sha->WorkDigest(header)};
    DataStream ss;
    ss << header;
    BOOST_REQUIRE_EQUAL(ss.size(), 164U);
    BOOST_CHECK_EQUAL(d0, Consensus::Sha256dBytes(std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(ss.data()), 80}));

    header.m_nonce2 = 1;
    BOOST_CHECK_EQUAL(sha->WorkDigest(header), d0);
    BOOST_CHECK(!sha->TailRule(header));
    header.m_nonce2 = 0;
    BOOST_CHECK(sha->TailRule(header));
    header.m_txcount = 1;
    BOOST_CHECK(sha->TailRule(header));
    const uint256 id0{header.GetBlockIdentity()};
    header.m_nonce2 = 1;
    BOOST_CHECK(header.GetBlockIdentity() != id0);
}

BOOST_AUTO_TEST_CASE(v1_header_does_not_decode_fp8)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus()};
    CBlockHeader header;
    header.m_header_v2 = false;
    header.nVersion = static_cast<int32_t>(2u << 8);
    BOOST_CHECK(!header.m_header_v2);
    BOOST_CHECK(!Consensus::DecodeWorkKindTag(header.GetCompleteVersion()));
    BOOST_CHECK(!Consensus::CheckWorkKindHeader(header, params));
}

BOOST_AUTO_TEST_CASE(sniff_wrong_tag_rejected)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus()};
    CBlockHeader header;
    header.m_header_v2 = true;
    header.nVersion = 4;
    header.nNonce = 1;
    Consensus::ApplyWorkKindTag(header, Consensus::WorkKindTag::BLAKE2B);
    const Consensus::WorkKind* blake{Consensus::LookupWorkKind(Consensus::WorkKindTag::BLAKE2B)};
    const Consensus::WorkKind* sha{Consensus::LookupWorkKind(Consensus::WorkKindTag::SHA256D)};
    const uint256 blake_d{blake->WorkDigest(header)};
    Consensus::ApplyWorkKindTag(header, Consensus::WorkKindTag::SHA256D);
    header.m_nonce2 = 0;
    BOOST_REQUIRE(sha->TailRule(header));
    const uint256 sha_d{sha->WorkDigest(header)};
    BOOST_CHECK(blake_d != sha_d);
    BOOST_CHECK_EQUAL(blake->WorkDigest(header), header.GetHash());
    BOOST_CHECK(sha->WorkDigest(header) != header.GetHash());
    header.nBits = 0;
    BOOST_CHECK(!sha->Check(header, header.nBits, params));
    BOOST_CHECK(!Consensus::CheckWorkKindHeader(header, params));
}

BOOST_AUTO_TEST_SUITE_END()
