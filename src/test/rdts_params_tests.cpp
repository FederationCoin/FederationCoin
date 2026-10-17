// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/flex_weight.h>
#include <consensus/params.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(rdts_params_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rdts_always_on_header_v2)
{
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params{CreateChainParams(ArgsManager{}, chain)};
        BOOST_CHECK(params->GenesisBlock().m_header_v2);
    }
}

BOOST_AUTO_TEST_CASE(reduced_data_weight_cap)
{
    // A block that fits in 2,400,000 weight is inside the cap.
    // A block over that cap is not. 800,000 was the old cap.
    BOOST_CHECK_EQUAL(Consensus::MIN_FLEX_BLOCK_WEIGHT, 2400000U);
    BOOST_CHECK(800000U < Consensus::MIN_FLEX_BLOCK_WEIGHT);
    BOOST_CHECK(2400000U <= Consensus::MIN_FLEX_BLOCK_WEIGHT);
    BOOST_CHECK(2400001U > Consensus::MIN_FLEX_BLOCK_WEIGHT);
}

BOOST_AUTO_TEST_SUITE_END()
