// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/work/kind.h>
#include <consensus/work/retarget.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

static CBlockHeader HeaderForKind(Consensus::WorkKindTag tag)
{
    CBlockHeader header;
    header.m_header_v2 = true;
    header.nVersion = 1;
    Consensus::ApplyWorkKindTag(header, tag);
    return header;
}

/** Linked fake index chain. Times at spacing unless time_step is set. */
static std::vector<CBlockIndex> MakeIndexChain(int count, int64_t genesis_time, int64_t time_step, const uint256& start_s)
{
    std::vector<CBlockIndex> blocks(count);
    for (int i = 0; i < count; ++i) {
        blocks[i].nHeight = i;
        blocks[i].nTime = static_cast<unsigned int>(genesis_time + i * time_step);
        blocks[i].nWorkScale = start_s;
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        if (i) blocks[i].BuildSkip();
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i]) : GetBlockProof(blocks[i]);
    }
    return blocks;
}

BOOST_AUTO_TEST_CASE(work_scale_genesis_adds_one)
{
    CBlockIndex genesis;
    genesis.nHeight = 0;
    genesis.nWorkScale = Consensus::WorkScaleOne();
    BOOST_CHECK_EQUAL(GetBlockProof(genesis), 1);
}

BOOST_AUTO_TEST_CASE(work_scale_s4_adds_four)
{
    CBlockIndex idx;
    idx.nWorkScale = ArithToUint256(arith_uint256{4});
    BOOST_CHECK_EQUAL(GetBlockProof(idx), 4);
}

BOOST_AUTO_TEST_CASE(scale_zero_rescued)
{
    const uint256 s{Consensus::ScaleAfterWindow(uint256::ZERO, 120, 30)};
    BOOST_CHECK_EQUAL(UintToArith256(s), 4); // rescued 1 * 120 / 30
}

BOOST_AUTO_TEST_CASE(scale_times_four_and_div_four)
{
    BOOST_CHECK_EQUAL(UintToArith256(Consensus::ScaleAfterWindow(uint256::ONE, 86400, 21600)), 4);
    BOOST_CHECK_EQUAL(UintToArith256(Consensus::ScaleAfterWindow(ArithToUint256(arith_uint256{4}), 86400, 345600)), 1);
}

BOOST_AUTO_TEST_CASE(retarget_fast_window_multiplies_s)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::REGTEST);
    Consensus::Params params = chainParams->GetConsensus();
    params.fPowNoRetargeting = false;
    BOOST_CHECK_EQUAL(params.DifficultyAdjustmentInterval(), 120);

    // Heights 0..119. Fast timestamps (1s) so NextWorkScale at 119 clamps span to expected/4.
    auto blocks = MakeIndexChain(120, 1'000'000, /*time_step=*/1, Consensus::WorkScaleOne());
    const uint256 s{Consensus::NextWorkScale(&blocks[119], params)};
    BOOST_CHECK_EQUAL(UintToArith256(s), 4);

    // Off-boundary copy: height 118 -> next is 119, not a window end.
    BOOST_CHECK_EQUAL(UintToArith256(Consensus::NextWorkScale(&blocks[118], params)), 1);

    const unsigned nbits_s1{Consensus::LookupWorkKind(Consensus::WorkKindTag::BLAKE2B)->ExpectedNBits(Consensus::WorkScaleOne(), params)};
    const unsigned nbits_s4{Consensus::LookupWorkKind(Consensus::WorkKindTag::BLAKE2B)->ExpectedNBits(s, params)};
    BOOST_CHECK_NE(nbits_s1, nbits_s4);
    for (size_t k{0}; k < Consensus::WORK_KIND_COUNT; ++k) {
        BOOST_CHECK_EQUAL(Consensus::WorkKindAt(k)->ExpectedNBits(s, params), Consensus::CompactTargetForScale(k, s, params));
    }
}

BOOST_AUTO_TEST_CASE(retarget_slow_window_divides_s)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::REGTEST);
    Consensus::Params params = chainParams->GetConsensus();
    params.fPowNoRetargeting = false;
    const uint256 s4{ArithToUint256(arith_uint256{4})};
    // 120 blocks, 4*expected spacing so clamp to expected*4, S := 4 * expected / (expected*4) = 1.
    const int64_t step{params.nPowTargetTimespan * 4 / 119};
    auto blocks = MakeIndexChain(120, 1'000'000, step, s4);
    const uint256 s{Consensus::NextWorkScale(&blocks[119], params)};
    BOOST_CHECK_EQUAL(UintToArith256(s), 1);
}

BOOST_AUTO_TEST_CASE(mixed_kind_window_one_s)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::REGTEST);
    Consensus::Params params = chainParams->GetConsensus();
    params.fPowNoRetargeting = false;
    auto blocks = MakeIndexChain(120, 1'000'000, 1, Consensus::WorkScaleOne());
    const uint256 s{Consensus::NextWorkScale(&blocks[119], params)};
    BOOST_CHECK_EQUAL(UintToArith256(s), 4);
    // Placeholders share T0 until pow-calibrate, so compact may match; S is shared.
    const unsigned b{Consensus::LookupWorkKind(Consensus::WorkKindTag::BLAKE2B)->ExpectedNBits(s, params)};
    const unsigned sha{Consensus::LookupWorkKind(Consensus::WorkKindTag::SHA256D)->ExpectedNBits(s, params)};
    const unsigned fp8{Consensus::LookupWorkKind(Consensus::WorkKindTag::FP8_GYM)->ExpectedNBits(s, params)};
    const unsigned p2{Consensus::LookupWorkKind(Consensus::WorkKindTag::POSEIDON2)->ExpectedNBits(s, params)};
    BOOST_CHECK_EQUAL(b, sha);
    BOOST_CHECK_EQUAL(sha, fp8);
    BOOST_CHECK_EQUAL(fp8, p2);
    CBlockHeader h_sha{HeaderForKind(Consensus::WorkKindTag::SHA256D)};
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[119], &h_sha, params), sha);
    CBlockHeader h_b{HeaderForKind(Consensus::WorkKindTag::BLAKE2B)};
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[119], &h_b, params), b);
    // Consecutive mixed kinds with distinct compact must be allowed (Verge-adjacent).
    BOOST_CHECK(PermittedDifficultyTransition(params, 120, b, b + 1));
}

BOOST_AUTO_TEST_CASE(halving_heights_do_not_move_s)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::REGTEST);
    Consensus::Params params = chainParams->GetConsensus();
    params.fPowNoRetargeting = false;
    BOOST_CHECK_EQUAL(params.nSubsidyHalvingInterval, 160);
    auto blocks = MakeIndexChain(162, 1'000'000, params.nPowTargetSpacing, Consensus::WorkScaleOne());
    BOOST_CHECK_EQUAL(UintToArith256(Consensus::NextWorkScale(&blocks[158], params)), 1);
    BOOST_CHECK_EQUAL(UintToArith256(Consensus::NextWorkScale(&blocks[159], params)), 1);
    BOOST_CHECK_EQUAL(UintToArith256(Consensus::NextWorkScale(&blocks[160], params)), 1);
    BOOST_CHECK_EQUAL(UintToArith256(Consensus::NextWorkScale(&blocks[119], params)), 1); // even spacing, S stays 1
    for (int h : {119, 120, 121, 159, 160, 161}) {
        for (size_t k{0}; k < Consensus::WORK_KIND_COUNT; ++k) {
            BOOST_CHECK(Consensus::WorkKindAt(k)->EnabledAt(h));
        }
    }
}

BOOST_AUTO_TEST_CASE(main_interval_and_halving_bounds)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    BOOST_CHECK_EQUAL(params.DifficultyAdjustmentInterval(), 1680);
    BOOST_CHECK_EQUAL(params.nSubsidyHalvingInterval, 210000);
    auto blocks = MakeIndexChain(1681, 1'000'000, 1, Consensus::WorkScaleOne());
    Consensus::Params live = params;
    live.fPowNoRetargeting = false;
    const uint256 s{Consensus::NextWorkScale(&blocks[1679], live)};
    BOOST_CHECK_EQUAL(UintToArith256(s), 4);
    BOOST_CHECK_EQUAL(UintToArith256(Consensus::NextWorkScale(&blocks[1678], live)), 1);
    for (int h : {209999, 210000, 210001}) {
        for (size_t k{0}; k < Consensus::WORK_KIND_COUNT; ++k) {
            BOOST_CHECK(Consensus::WorkKindAt(k)->EnabledAt(h));
            (void)Consensus::CompactTargetForScale(k, s, params);
        }
    }
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);
    // Twelve-minute blocks. 600 was the old ten-minute spacing.
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 12 * 60);
    // Window stays one timespan of wall clock: 1680 on the two-week nets, 120 on regtest.
    const int64_t expected_window = consensus.nPowTargetTimespan / consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(consensus.nMinerConfirmationWindow, expected_window);
    const bool ninety_percent = chain_type == ChainType::MAIN || chain_type == ChainType::SIGNET;
    BOOST_CHECK_EQUAL(consensus.nRuleChangeActivationThreshold, expected_window * (ninety_percent ? 90 : 75) / 100);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // ScaleAfterWindow multiplies S by expected timespan. Genesis S=1 fits.
    if (!consensus.fPowNoRetargeting) {
        const arith_uint256 one{1};
        const arith_uint256 max{~arith_uint256(0)};
        BOOST_CHECK(one <= max / arith_uint256{static_cast<uint64_t>(consensus.nPowTargetTimespan)});
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

/* Mixed-kind compact nBits are not compared to the previous header. */
BOOST_AUTO_TEST_CASE(permitted_difficulty_transition_gate)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& params = chainParams->GetConsensus();
    BOOST_CHECK(PermittedDifficultyTransition(params, 1, 0x1e00ffff, 0x1d00ffff));
    BOOST_CHECK(PermittedDifficultyTransition(params, 1680, 0x1e00ffff, 0x1c00ffff));
}

BOOST_AUTO_TEST_SUITE_END()
