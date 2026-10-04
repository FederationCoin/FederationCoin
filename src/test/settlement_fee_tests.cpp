// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/settlement_fee.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(settlement_fee_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(minimum_fee_rate)
{
    BOOST_CHECK_EQUAL(MinimumFee(0), 0);
    BOOST_CHECK_EQUAL(MinimumFee(11), 0);
    BOOST_CHECK_EQUAL(MinimumFee(12), 1);
    BOOST_CHECK_EQUAL(MinimumFee(1075), 89);
    BOOST_CHECK(FeeMeetsMinimumRate(0, 0));
    BOOST_CHECK(FeeMeetsMinimumRate(0, 11));
    BOOST_CHECK(!FeeMeetsMinimumRate(0, 12));
    BOOST_CHECK(FeeMeetsMinimumRate(1, 12));
    // A simple ML-DSA payment is about 1,075 virtual bytes: 88 is short, 89 meets the floor.
    BOOST_CHECK(!FeeMeetsMinimumRate(88, 1075));
    BOOST_CHECK(FeeMeetsMinimumRate(89, 1075));
    BOOST_CHECK_EQUAL(MinimumFee(1945), 162);
    BOOST_CHECK(!FeeMeetsMinimumRate(161, 1945));
    BOOST_CHECK(FeeMeetsMinimumRate(162, 1945));
    BOOST_CHECK_EQUAL(MinimumFee(137), 11);
    BOOST_CHECK(!FeeMeetsMinimumRate(10, 137));
    BOOST_CHECK(FeeMeetsMinimumRate(11, 137));
    // Any higher fee is valid, including the old 3-token rate.
    BOOST_CHECK(FeeMeetsMinimumRate(1075 * 3, 1075));
}

BOOST_AUTO_TEST_CASE(data_carrier_nonce_and_scriptsig)
{
    CScript commitment;
    commitment.resize(38);
    commitment[0] = OP_RETURN;
    commitment[1] = 0x24;
    commitment[2] = 0xaa;
    commitment[3] = 0x21;
    commitment[4] = 0xa9;
    commitment[5] = 0xed;
    BOOST_CHECK(Consensus::IsWitnessCommitmentScript(commitment));

    CMutableTransaction user;
    user.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(4, 1));
    TxValidationState state;
    BOOST_CHECK(!Consensus::RejectUserDataCarrier(CTransaction{user}, state));

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vout.emplace_back(0, commitment);
    TxValidationState coinbase_state;
    BOOST_CHECK(Consensus::RejectCoinbaseDataCarrier(CTransaction{coinbase}, coinbase_state));
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(2, 2));
    TxValidationState loose_state;
    BOOST_CHECK(!Consensus::RejectCoinbaseDataCarrier(CTransaction{coinbase}, loose_state));

    BOOST_CHECK(Consensus::WitnessNonceIsZero(std::vector<unsigned char>(32, 0)));
    std::vector<unsigned char> marked(32, 0);
    marked[3] = 1;
    BOOST_CHECK(!Consensus::WitnessNonceIsZero(marked));
    BOOST_CHECK(!Consensus::WitnessNonceIsZero(std::vector<unsigned char>(31, 0)));

    BOOST_CHECK(Consensus::MiningCoinbaseScriptSigFits(2));
    BOOST_CHECK(Consensus::MiningCoinbaseScriptSigFits(MAX_COINBASE_SCRIPTSIG_SIZE));
    BOOST_CHECK(!Consensus::MiningCoinbaseScriptSigFits(MAX_COINBASE_SCRIPTSIG_SIZE + 1));
    BOOST_CHECK(SeedsServiceFlags() & NODE_REDUCED_DATA);
}

BOOST_AUTO_TEST_SUITE_END()
