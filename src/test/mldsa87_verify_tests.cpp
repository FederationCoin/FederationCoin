// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa87_spend.h>
#include <test/util/setup_common.h>

#include <array>
#include <span>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mldsa87_verify_tests, BasicTestingSetup)

static std::array<unsigned char, 32> Message(unsigned char mark)
{
    std::array<unsigned char, 32> message{};
    message.fill(mark);
    return message;
}

BOOST_AUTO_TEST_CASE(wrong_length_rejected)
{
    const std::array<unsigned char, Consensus::MLDSA87_PUBLIC_KEY_SIZE> pubkey{};
    const std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE> signature{};
    const auto message{Message(1)};
    std::array<unsigned char, Consensus::MLDSA87_PUBLIC_KEY_SIZE - 1> short_pubkey{};
    std::array<unsigned char, Consensus::MLDSA87_PUBLIC_KEY_SIZE + 1> long_pubkey{};
    std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE - 1> short_signature{};
    std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE + 1> long_signature{};

    BOOST_CHECK(!Consensus::MlDsa87Verify(short_pubkey, signature, message));
    BOOST_CHECK(!Consensus::MlDsa87Verify(long_pubkey, signature, message));
    BOOST_CHECK(!Consensus::MlDsa87Verify(pubkey, short_signature, message));
    BOOST_CHECK(!Consensus::MlDsa87Verify(pubkey, long_signature, message));
    BOOST_CHECK(!Consensus::MlDsa87Verify(std::span<const unsigned char>{}, signature, message));
}

BOOST_AUTO_TEST_CASE(round_trip_verifies)
{
    std::array<unsigned char, Consensus::MLDSA87_SEED_SIZE> seed{};
    seed[0] = 7;
    Consensus::MlDsa87Keypair key;
    BOOST_REQUIRE(Consensus::MlDsa87Keygen(seed, key));

    const auto message{Message(9)};
    std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE> signature{};
    BOOST_REQUIRE(Consensus::MlDsa87Sign(key, message, signature));
    BOOST_CHECK(Consensus::MlDsa87Verify(key.pubkey, signature, message));

    const auto other{Message(8)};
    BOOST_CHECK(!Consensus::MlDsa87Verify(key.pubkey, signature, other));
}

BOOST_AUTO_TEST_SUITE_END()
