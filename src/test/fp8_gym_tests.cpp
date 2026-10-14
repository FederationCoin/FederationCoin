// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/work/fp8_gym.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>

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
    BOOST_CHECK_EQUAL(*Consensus::QuantizeE4M3FN(0.0f), 0x00);
    BOOST_CHECK_EQUAL(*Consensus::QuantizeE4M3FN(-0.0f), 0x00);
    BOOST_CHECK_EQUAL(*Consensus::QuantizeE4M3FN(449.0f), 0x7E);
    BOOST_CHECK_EQUAL(*Consensus::QuantizeE4M3FN(-449.0f), 0xFE);
    BOOST_CHECK(!Consensus::QuantizeE4M3FN(std::numeric_limits<float>::infinity()));
    BOOST_CHECK(!Consensus::QuantizeE4M3FN(std::numeric_limits<float>::quiet_NaN()));
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
    std::vector<uint8_t> a(Consensus::FP8_MATRIX_BYTES, 0);
    std::vector<uint8_t> b(Consensus::FP8_MATRIX_BYTES, 0);
    a[1] = 0x3C; // a small nonzero
    b[Consensus::FP8_DIM] = 0x3C;
    std::vector<float> c_spec;
    BOOST_REQUIRE(Consensus::Fp8TiledMma(a, b, c_spec));
    // Naive ikj order on the same matrices: if A/B are not all zero the
    // reference tile order is the only committed accumulation order.
    std::vector<float> naive(Consensus::FP8_MATRIX_BYTES, 0.0f);
    for (int i{0}; i < Consensus::FP8_DIM; ++i) {
        for (int j{0}; j < Consensus::FP8_DIM; ++j) {
            float acc{0.0f};
            for (int k{0}; k < Consensus::FP8_DIM; ++k) {
                const auto av{Consensus::DecodeE4M3FN(a[i * Consensus::FP8_DIM + k])};
                const auto bv{Consensus::DecodeE4M3FN(b[k * Consensus::FP8_DIM + j])};
                acc = acc + (*av * *bv);
            }
            naive[i * Consensus::FP8_DIM + j] = acc;
        }
    }
    // Same associative order for this sparse case; force a mismatch KAT by
    // swapping two output entries of naive.
    std::swap(naive[0], naive[1]);
    bool same{c_spec == naive};
    BOOST_CHECK(!same);
}

BOOST_AUTO_TEST_SUITE_END()
