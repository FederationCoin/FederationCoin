// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa_spend.h>
#include <crypto/blake2b.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <array>
#include <span>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mldsa_witness_tests, BasicTestingSetup)

static uint256 TaggedKeyHash(std::span<const unsigned char> pubkey)
{
    std::vector<unsigned char> preimage;
    preimage.push_back(0x0f);
    const std::string tag{"FCN-MLDSA44-KEY"};
    preimage.insert(preimage.end(), tag.begin(), tag.end());
    preimage.insert(preimage.end(), pubkey.begin(), pubkey.end());
    std::array<unsigned char, 32> out{};
    BOOST_REQUIRE_EQUAL(blake2b_nokey(out.data(), out.size(), preimage.data(), preimage.size()), 0);
    return uint256{Span<const unsigned char>{out.data(), out.size()}};
}

BOOST_AUTO_TEST_CASE(key_hash_uses_the_key_tag)
{
    std::array<unsigned char, Consensus::MLDSA44_PUBLIC_KEY_SIZE> pubkey{};
    pubkey[0] = 1;
    BOOST_CHECK(Consensus::MlDsa44KeyHash(pubkey) == TaggedKeyHash(pubkey));
    BOOST_CHECK(Consensus::MlDsa44SingleKeyProgram(pubkey) == Consensus::MlDsa44KeyHash(pubkey));
}

BOOST_AUTO_TEST_CASE(extra_item_and_wrong_length_rejected)
{
    std::array<unsigned char, Consensus::MLDSA44_PUBLIC_KEY_SIZE> pubkey{};
    pubkey[0] = 2;
    std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> signature{};
    const auto program{Consensus::MlDsa44SingleKeyProgram(pubkey)};
    const std::array<unsigned char, 32> sighash{1};

    std::vector<std::vector<unsigned char>> witness;
    witness.emplace_back(pubkey.begin(), pubkey.end());
    witness.emplace_back(signature.begin(), signature.end());
    witness.push_back({0x50});
    BOOST_CHECK(!Consensus::CheckSingleKeySpend(program, witness, sighash));

    witness.pop_back();
    witness[0].pop_back();
    BOOST_CHECK(!Consensus::CheckSingleKeySpend(program, witness, sighash));

    witness[0].push_back(0);
    witness[1].push_back(0);
    BOOST_CHECK(!Consensus::CheckSingleKeySpend(program, witness, sighash));
}

BOOST_AUTO_TEST_CASE(single_key_spend_accepted)
{
    std::array<unsigned char, Consensus::MLDSA44_SEED_SIZE> seed{};
    seed[0] = 4;
    Consensus::MlDsa44Keypair key;
    BOOST_REQUIRE(Consensus::MlDsa44Keygen(seed, key));
    const std::array<unsigned char, 32> sighash{3};
    std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> signature{};
    BOOST_REQUIRE(Consensus::MlDsa44Sign(key, sighash, signature));

    const auto program{Consensus::MlDsa44SingleKeyProgram(key.pubkey)};
    std::vector<std::vector<unsigned char>> witness;
    witness.emplace_back(key.pubkey.begin(), key.pubkey.end());
    witness.emplace_back(signature.begin(), signature.end());
    BOOST_CHECK(Consensus::CheckSingleKeySpend(program, witness, sighash));
}

BOOST_AUTO_TEST_CASE(unrelated_hash_is_a_burn)
{
    std::array<unsigned char, Consensus::MLDSA44_PUBLIC_KEY_SIZE> pubkey{};
    pubkey[0] = 5;
    std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> signature{};
    signature[0] = 6;
    const std::array<unsigned char, 32> sighash{2};

    uint256 burn;
    std::fill(burn.begin(), burn.end(), static_cast<unsigned char>(0x11));
    const CScript output = CScript() << OP_0 << std::vector<unsigned char>(burn.begin(), burn.end());
    BOOST_CHECK_EQUAL(output.size(), 34U);

    std::vector<std::vector<unsigned char>> witness;
    witness.emplace_back(pubkey.begin(), pubkey.end());
    witness.emplace_back(signature.begin(), signature.end());
    BOOST_CHECK(!Consensus::CheckSingleKeySpend(burn, witness, sighash));
}

BOOST_AUTO_TEST_SUITE_END()
