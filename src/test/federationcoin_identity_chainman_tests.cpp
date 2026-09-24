// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <consensus/params.h>
#include <deploymentstatus.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(federationcoin_identity_chainman_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(taproot_not_active_so_block_flags_omit_it)
{
    LOCK(::cs_main);
    const CBlockIndex* genesis{Assert(m_node.chainman)->ActiveChain().Genesis()};
    BOOST_REQUIRE(genesis);
    BOOST_CHECK(!DeploymentActiveAt(*genesis, *m_node.chainman, Consensus::DEPLOYMENT_TAPROOT));
}

BOOST_AUTO_TEST_SUITE_END()
