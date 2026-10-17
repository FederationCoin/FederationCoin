// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/work/cost.h>
#include <consensus/work/kind.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(work_cost_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(spec_counts_match_the_gym_and_hashes)
{
    BOOST_CHECK_EQUAL(Consensus::kFp8ExpandCount, 2048);
    BOOST_CHECK_EQUAL(Consensus::kFp8OutB2bc, 513);
    BOOST_CHECK_EQUAL(Consensus::kFp8Macs, 256ull * 256ull * 256ull);
    BOOST_CHECK_EQUAL(Consensus::kSha256dCompressions, 3);
    BOOST_CHECK_EQUAL(Consensus::kPoseidon2Permutes, 5);
    BOOST_CHECK_EQUAL(Consensus::kPoseidon2PreimageB2bc, 2);
    BOOST_CHECK_EQUAL(Consensus::kFp8SeedB2bc, 2);
    BOOST_CHECK_EQUAL(Consensus::kFp8Quantizes, 65536);
}

BOOST_AUTO_TEST_CASE(conversions_floor_toward_zero_and_sha_is_exact)
{
    BOOST_CHECK_EQUAL(Consensus::kSha256dCompressions % Consensus::kSha256CompressionsPerB2bc, 0);
    BOOST_CHECK_EQUAL(Consensus::Sha256dHashCostB2bc(), 1);
    BOOST_CHECK_EQUAL(Consensus::Poseidon2HashCostB2bc(), 32);
    const uint64_t macs_b2bc{Consensus::kFp8Macs / Consensus::kFp8MacsPerB2bc};
    const uint64_t quant_b2bc{Consensus::kFp8Quantizes / Consensus::kFp8QuantizesPerB2bc};
    BOOST_CHECK_EQUAL(macs_b2bc * Consensus::kFp8MacsPerB2bc + (Consensus::kFp8Macs % Consensus::kFp8MacsPerB2bc),
                      Consensus::kFp8Macs);
    BOOST_CHECK_NE(Consensus::kFp8Macs % Consensus::kFp8MacsPerB2bc, 0);
    BOOST_CHECK_EQUAL(quant_b2bc * Consensus::kFp8QuantizesPerB2bc + (Consensus::kFp8Quantizes % Consensus::kFp8QuantizesPerB2bc),
                      Consensus::kFp8Quantizes);
    const uint64_t d{Consensus::kFp8SeedB2bc + Consensus::kFp8ExpandCount + macs_b2bc + quant_b2bc + Consensus::kFp8OutB2bc};
    BOOST_CHECK_EQUAL(Consensus::Fp8KnobDiscountB2bc(), d);
}

BOOST_AUTO_TEST_CASE(kinds_own_offsets)
{
    BOOST_CHECK_EQUAL(Consensus::LookupWorkKind(Consensus::WorkKindTag::BLAKE2B)->HashCostOffsetB2bc(), 1);
    BOOST_CHECK_EQUAL(Consensus::LookupWorkKind(Consensus::WorkKindTag::BLAKE2B)->KnobDiscountB2bc(), 1);
    BOOST_CHECK_EQUAL(Consensus::LookupWorkKind(Consensus::WorkKindTag::SHA256D)->HashCostOffsetB2bc(), Consensus::Sha256dHashCostB2bc());
    BOOST_CHECK_EQUAL(Consensus::LookupWorkKind(Consensus::WorkKindTag::SHA256D)->KnobDiscountB2bc(), 1);
    BOOST_CHECK_EQUAL(Consensus::LookupWorkKind(Consensus::WorkKindTag::FP8_GYM)->HashCostOffsetB2bc(), 1);
    BOOST_CHECK_EQUAL(Consensus::LookupWorkKind(Consensus::WorkKindTag::FP8_GYM)->KnobDiscountB2bc(), Consensus::Fp8KnobDiscountB2bc());
    BOOST_CHECK_EQUAL(Consensus::LookupWorkKind(Consensus::WorkKindTag::POSEIDON2)->HashCostOffsetB2bc(), Consensus::Poseidon2HashCostB2bc());
    BOOST_CHECK_EQUAL(Consensus::LookupWorkKind(Consensus::WorkKindTag::POSEIDON2)->KnobDiscountB2bc(), 1);
}

BOOST_AUTO_TEST_CASE(genesis_target_in_range_and_overflow)
{
    const uint256 six{Consensus::GenesisTargetForKind(uint256::ONE, 2, 3).value_or(uint256{})};
    BOOST_CHECK_EQUAL(UintToArith256(six), 6);
    BOOST_CHECK(!Consensus::GenesisTargetForKind(uint256{}, 1, 1));
    BOOST_CHECK(!Consensus::GenesisTargetForKind(uint256::ONE, 0, 1));
    BOOST_CHECK(!Consensus::GenesisTargetForKind(uint256::ONE, 1, 0));
    const uint256 max{ArithToUint256(~arith_uint256(0))};
    BOOST_CHECK(!Consensus::GenesisTargetForKind(max, 2, 1));
    BOOST_CHECK(Consensus::GenesisTargetForKind(max, 1, 1));
}

BOOST_AUTO_TEST_CASE(main_gym_t0_is_discounted_below_cap)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus()};
    const size_t blake{static_cast<size_t>(Consensus::WorkKindTag::BLAKE2B)};
    const size_t fp8{static_cast<size_t>(Consensus::WorkKindTag::FP8_GYM)};
    const size_t p2{static_cast<size_t>(Consensus::WorkKindTag::POSEIDON2)};
    BOOST_CHECK(UintToArith256(params.powT0[fp8]) > UintToArith256(params.powT0[blake]));
    BOOST_CHECK(UintToArith256(params.powT0[p2]) > UintToArith256(params.powT0[blake]));
    BOOST_CHECK(UintToArith256(params.powT0[fp8]) < UintToArith256(params.powLimit));
    BOOST_CHECK(UintToArith256(params.powT0[fp8]) < UintToArith256(params.powLimitKind[fp8]));
    const auto expect{Consensus::GenesisTargetForKind(params.powT0[blake], 1, Consensus::Fp8KnobDiscountB2bc())};
    BOOST_REQUIRE(expect);
    BOOST_CHECK_EQUAL(*expect, params.powT0[fp8]);
}

BOOST_AUTO_TEST_CASE(regtest_cannot_ease_past_encoding_max)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus()};
    const size_t blake{static_cast<size_t>(Consensus::WorkKindTag::BLAKE2B)};
    const size_t fp8{static_cast<size_t>(Consensus::WorkKindTag::FP8_GYM)};
    BOOST_CHECK_EQUAL(params.powT0[fp8], params.powT0[blake]);
}

BOOST_AUTO_TEST_SUITE_END()
