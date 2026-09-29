// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/params.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(rdts_params_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rdts_active_at_height_only)
{
    constexpr int H{1000};
    Consensus::Params params;
    params.Blake2bHeight = H;

    BOOST_CHECK(!params.RdtsActiveAt(H - 1));
    BOOST_CHECK(params.RdtsActiveAt(H));
    BOOST_CHECK(params.RdtsActiveAt(H + 1));

    params.Blake2bHeight = std::numeric_limits<int>::max();
    BOOST_CHECK(!params.RdtsActiveAt(std::numeric_limits<int>::max() - 1));
    BOOST_CHECK(params.RdtsActiveAt(std::numeric_limits<int>::max()));
}

BOOST_AUTO_TEST_CASE(rdts_active_from_first_block)
{
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params{CreateChainParams(ArgsManager{}, chain)};
        const Consensus::Params& c{params->GetConsensus()};
        BOOST_CHECK_EQUAL(c.Blake2bHeight, 0);
        BOOST_CHECK(c.RdtsActiveAt(0));
    }
}

BOOST_AUTO_TEST_SUITE_END()
