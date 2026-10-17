// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa44_spend.h>
#include <consensus/mldsa_seed.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <vector>

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

BOOST_AUTO_TEST_CASE(policy_xprvs_scriptpubkey_vector)
{
    const std::vector<unsigned char> xprv0(32, 0xa1);
    const std::vector<unsigned char> xprv1(32, 0xb2);
    std::array<unsigned char, Consensus::MLDSA_DERIVED_SEED_SIZE> d0{};
    std::array<unsigned char, Consensus::MLDSA_DERIVED_SEED_SIZE> d1{};
    const uint32_t i0{Consensus::MlDsaKdfIndex(0 * 12 + 0, false)};
    const uint32_t i1{Consensus::MlDsaKdfIndex(0 * 12 + 1, false)};
    BOOST_REQUIRE(Consensus::DeriveMlDsaSeed(xprv0, Consensus::MlDsaSeedKind::Policy44, i0, d0));
    BOOST_REQUIRE(Consensus::DeriveMlDsaSeed(xprv1, Consensus::MlDsaSeedKind::Policy44, i1, d1));
    Consensus::MlDsa44Keypair k0;
    Consensus::MlDsa44Keypair k1;
    BOOST_REQUIRE(Consensus::MlDsa44Keygen(d0, k0));
    BOOST_REQUIRE(Consensus::MlDsa44Keygen(d1, k1));
    std::vector<uint256> hashes{Consensus::MlDsa44KeyHash(k0.pubkey), Consensus::MlDsa44KeyHash(k1.pubkey)};
    std::sort(hashes.begin(), hashes.end());
    const auto program{Consensus::MlDsa44PolicyProgram(1, hashes)};
    BOOST_REQUIRE(program);
    BOOST_CHECK_EQUAL(HexStr(*program), "51202b84379230309a0492bcb24fd24d52b1b81f89cfc4f821890770fd0e7cf335d920bf4fc5ead1b5876b86d9083d563608f8446e6f2b8288be542c2c99e213b66017525151bc");
}

BOOST_AUTO_TEST_SUITE_END()
