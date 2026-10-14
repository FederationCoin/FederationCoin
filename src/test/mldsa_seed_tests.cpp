// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa_seed.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mldsa_seed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_seed_fails)
{
    std::array<unsigned char, 32> out{};
    BOOST_CHECK(!Consensus::DeriveMlDsaSeed({}, Consensus::MlDsaSeedKind::Dilithium87, 0, out));
}

BOOST_AUTO_TEST_CASE(kind_and_index_diverge)
{
    const std::vector<unsigned char> seed(32, 0x11);
    std::array<unsigned char, 32> a{};
    std::array<unsigned char, 32> b{};
    std::array<unsigned char, 32> c{};
    BOOST_REQUIRE(Consensus::DeriveMlDsaSeed(seed, Consensus::MlDsaSeedKind::Dilithium44, 0, a));
    BOOST_REQUIRE(Consensus::DeriveMlDsaSeed(seed, Consensus::MlDsaSeedKind::Dilithium87, 0, b));
    BOOST_REQUIRE(Consensus::DeriveMlDsaSeed(seed, Consensus::MlDsaSeedKind::Dilithium44, 1, c));
    BOOST_CHECK(a != b);
    BOOST_CHECK(a != c);
    BOOST_CHECK(b != c);
}

BOOST_AUTO_TEST_CASE(pinned_vector)
{
    const std::vector<unsigned char> seed(32, 0x42);
    std::array<unsigned char, 32> out{};
    BOOST_REQUIRE(Consensus::DeriveMlDsaSeed(seed, Consensus::MlDsaSeedKind::Dilithium87, 7, out));
    BOOST_CHECK_EQUAL(HexStr(out), "8d3755b302d8a066e6ae846b00e329cfd597043e812dc509b240876c171e8f68");
}

BOOST_AUTO_TEST_CASE(change_bit_diverges)
{
    const std::vector<unsigned char> seed(32, 0x11);
    std::array<unsigned char, 32> recv{};
    std::array<unsigned char, 32> change{};
    const uint32_t recv_i{Consensus::MlDsaKdfIndex(0, false)};
    const uint32_t change_i{Consensus::MlDsaKdfIndex(0, true)};
    BOOST_CHECK_EQUAL(recv_i, 0u);
    BOOST_CHECK_EQUAL(change_i, 0x80000000u);
    BOOST_REQUIRE(Consensus::DeriveMlDsaSeed(seed, Consensus::MlDsaSeedKind::Dilithium87, recv_i, recv));
    BOOST_REQUIRE(Consensus::DeriveMlDsaSeed(seed, Consensus::MlDsaSeedKind::Dilithium87, change_i, change));
    BOOST_CHECK(recv != change);
}

BOOST_AUTO_TEST_SUITE_END()
