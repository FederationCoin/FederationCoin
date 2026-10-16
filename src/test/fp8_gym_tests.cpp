// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/work/fp8_gym.h>
#include <consensus/work/kind.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <cmath>
#include <limits>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(fp8_gym_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(decode_quantize_roundtrip_finite)
{
    BOOST_CHECK(!Consensus::DecodeE4M3FN(0x7F));
    BOOST_CHECK(!Consensus::DecodeE4M3FN(0xFF));
    BOOST_CHECK_EQUAL(*Consensus::DecodeE4M3FN(0x00), 0.0f);
    BOOST_CHECK_EQUAL(*Consensus::DecodeE4M3FN(0x7E), 448.0f);
    BOOST_CHECK_EQUAL(*Consensus::DecodeE4M3FN(0xFE), -448.0f);
    BOOST_CHECK_EQUAL(*Consensus::DecodeE4M3FN(0x78), 256.0f);
    BOOST_CHECK_EQUAL(Consensus::QuantizeE4M3FN(0.0f), 0x00);
    BOOST_CHECK_EQUAL(Consensus::QuantizeE4M3FN(-0.0f), 0x80);
    BOOST_CHECK_EQUAL(Consensus::QuantizeE4M3FN(std::ldexp(1.0f, -11)), 0x00);
    BOOST_CHECK_EQUAL(Consensus::QuantizeE4M3FN(-std::ldexp(1.0f, -11)), 0x80);
    BOOST_CHECK_EQUAL(Consensus::QuantizeE4M3FN(449.0f), 0x7E);
    BOOST_CHECK_EQUAL(Consensus::QuantizeE4M3FN(-449.0f), 0xFE);
    BOOST_CHECK_EQUAL(Consensus::QuantizeE4M3FN(std::numeric_limits<float>::infinity()), 0x7E);
    BOOST_CHECK_EQUAL(Consensus::QuantizeE4M3FN(-std::numeric_limits<float>::infinity()), 0xFE);
    const uint8_t nan_code{Consensus::QuantizeE4M3FN(std::numeric_limits<float>::quiet_NaN())};
    BOOST_CHECK((nan_code == 0x7F) || (nan_code == 0xFF));
}

BOOST_AUTO_TEST_CASE(qmma_k32_in_range)
{
    uint8_t a[32]{};
    uint8_t b[32]{};
    a[0] = 0x38;
    b[0] = 0x38;
    float out{99.0f};
    BOOST_REQUIRE(Consensus::Fp8QmmaK32(a, b, 0.0f, out));
    BOOST_CHECK_EQUAL(out, 1.0f);
    a[1] = 0x38;
    b[1] = 0x38;
    BOOST_REQUIRE(Consensus::Fp8QmmaK32(a, b, 0.0f, out));
    BOOST_CHECK_EQUAL(out, 2.0f);
}

BOOST_AUTO_TEST_CASE(qmma_k32_inf_c_saturates_on_pack)
{
    uint8_t a[32]{};
    uint8_t b[32]{};
    float out{};
    BOOST_REQUIRE(Consensus::Fp8QmmaK32(a, b, std::numeric_limits<float>::infinity(), out));
    BOOST_CHECK(std::isinf(out) && out > 0.0f);
    BOOST_CHECK_EQUAL(Consensus::QuantizeE4M3FN(out), 0x7E);
    BOOST_REQUIRE(Consensus::Fp8QmmaK32(a, b, -std::numeric_limits<float>::infinity(), out));
    BOOST_CHECK(std::isinf(out) && out < 0.0f);
    BOOST_CHECK_EQUAL(Consensus::QuantizeE4M3FN(out), 0xFE);
}

BOOST_AUTO_TEST_CASE(all_zero_mma)
{
    std::vector<uint8_t> a(Consensus::FP8_MATRIX_BYTES, 0);
    std::vector<uint8_t> b(Consensus::FP8_MATRIX_BYTES, 0);
    std::vector<float> c;
    BOOST_REQUIRE(Consensus::Fp8TiledMma(a, b, c));
    for (float v : c) {
        BOOST_CHECK_EQUAL(v, 0.0f);
    }
    const auto packed{Consensus::Fp8QuantizeC(c)};
    BOOST_REQUIRE(packed);
    for (uint8_t byte : *packed) {
        BOOST_CHECK_EQUAL(byte, 0x00);
    }
}

BOOST_AUTO_TEST_CASE(max_finite_saturate)
{
    std::vector<uint8_t> a(Consensus::FP8_MATRIX_BYTES, 0x7E);
    std::vector<uint8_t> b(Consensus::FP8_MATRIX_BYTES, 0x7E);
    std::vector<float> c;
    BOOST_REQUIRE(Consensus::Fp8TiledMma(a, b, c));
    const auto packed{Consensus::Fp8QuantizeC(c)};
    BOOST_REQUIRE(packed);
    for (uint8_t byte : *packed) {
        BOOST_CHECK_EQUAL(byte, 0x7E);
    }
}

BOOST_AUTO_TEST_CASE(expand_remaps_nan_encodings)
{
    CBlockHeader header;
    header.m_header_v2 = true;
    header.nVersion = 1;
    std::vector<uint8_t> a, b;
    Consensus::Fp8ExpandAB(header, a, b);
    BOOST_REQUIRE_EQUAL(a.size(), static_cast<size_t>(Consensus::FP8_MATRIX_BYTES));
    for (uint8_t byte : a) {
        BOOST_CHECK_NE(byte & 0x7F, 0x7F);
    }
    for (uint8_t byte : b) {
        BOOST_CHECK_NE(byte & 0x7F, 0x7F);
    }
}

BOOST_AUTO_TEST_CASE(tile_order_change_fails)
{
    // a[0,1] and b[1,0] feed cell (0,0) only. Do not run a 256³ naive matmul.
    std::vector<uint8_t> a(Consensus::FP8_MATRIX_BYTES, 0);
    std::vector<uint8_t> b(Consensus::FP8_MATRIX_BYTES, 0);
    a[1] = 0x3C;
    b[Consensus::FP8_DIM] = 0x3C;
    std::vector<float> c_spec;
    BOOST_REQUIRE(Consensus::Fp8TiledMma(a, b, c_spec));
    BOOST_CHECK_NE(c_spec[0], 0.0f);
    BOOST_CHECK_EQUAL(c_spec[1], 0.0f);
}

BOOST_AUTO_TEST_CASE(golden_digest_all_zero)
{
    std::vector<uint8_t> packed(Consensus::FP8_MATRIX_BYTES, 0);
    BOOST_CHECK_EQUAL(
        Consensus::Fp8PackedCDigest(packed).ToString(),
        "d4e9f8cab33368de6bffa6058669b999fdcb36cff4a5ea0526fc611b9da31933");
}

BOOST_AUTO_TEST_CASE(golden_digest_all_max)
{
    std::vector<uint8_t> a(Consensus::FP8_MATRIX_BYTES, 0x7E);
    std::vector<uint8_t> b(Consensus::FP8_MATRIX_BYTES, 0x7E);
    std::vector<float> c;
    BOOST_REQUIRE(Consensus::Fp8TiledMma(a, b, c));
    const auto packed{Consensus::Fp8QuantizeC(c)};
    BOOST_REQUIRE(packed);
    BOOST_CHECK_EQUAL(
        Consensus::Fp8PackedCDigest(*packed).ToString(),
        "41ca676ae4b108366a3dc3789805bc2a0d46cdc4830500e2d261d3ea4470f6c7");
}

BOOST_AUTO_TEST_CASE(golden_digest_frozen_header)
{
    // 5070 Ti dump (fp8_blackwell_kat). Pin card is the spec.
    CBlockHeader header;
    header.m_header_v2 = true;
    header.nVersion = 4;
    Consensus::ApplyWorkKindTag(header, Consensus::WorkKindTag::FP8_GYM);
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce = 1;
    const auto digest{Consensus::Fp8GymDigest(header)};
    BOOST_REQUIRE(digest);
    BOOST_CHECK_EQUAL(
        digest->ToString(),
        "3332ec622e4c7ac62990a3323d2d62187fb4626b44757b5183cb7d2b97f41d74");
}

BOOST_AUTO_TEST_SUITE_END()
