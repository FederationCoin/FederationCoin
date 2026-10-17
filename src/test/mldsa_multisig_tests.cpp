// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa44_spend.h>
#include <test/util/setup_common.h>

#include <array>
#include <algorithm>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mldsa_multisig_tests, BasicTestingSetup)

struct Holder {
    Consensus::MlDsa44Keypair key;
    uint256 hash;
};

static Holder MakeHolder(unsigned char mark)
{
    std::array<unsigned char, Consensus::MLDSA44_SEED_SIZE> seed{};
    seed.fill(mark);
    Holder holder;
    BOOST_REQUIRE(Consensus::MlDsa44Keygen(seed, holder.key));
    holder.hash = Consensus::MlDsa44KeyHash(holder.key.pubkey);
    return holder;
}

static void AppendSigned(std::vector<std::vector<unsigned char>>& witness, const Holder& holder, std::span<const unsigned char> sighash)
{
    std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> signature{};
    BOOST_REQUIRE(Consensus::MlDsa44Sign(holder.key, sighash, signature));
    std::vector<unsigned char> item(holder.key.pubkey.begin(), holder.key.pubkey.end());
    item.insert(item.end(), signature.begin(), signature.end());
    witness.push_back(std::move(item));
}

static void AppendSkipped(std::vector<std::vector<unsigned char>>& witness)
{
    witness.emplace_back();
}

BOOST_AUTO_TEST_CASE(two_of_three)
{
    std::vector<Holder> holders;
    holders.push_back(MakeHolder(1));
    holders.push_back(MakeHolder(2));
    holders.push_back(MakeHolder(3));
    std::sort(holders.begin(), holders.end(), [](const Holder& a, const Holder& b) { return a.hash < b.hash; });

    const std::array<uint256, 3> hashes{holders[0].hash, holders[1].hash, holders[2].hash};
    const auto program{Consensus::MlDsa44PolicyProgram(2, hashes)};
    BOOST_REQUIRE(program.has_value());

    const std::array<unsigned char, 32> sighash{4};

    std::vector<std::vector<unsigned char>> one_signature;
    AppendSigned(one_signature, holders[0], sighash);
    AppendSkipped(one_signature);
    AppendSkipped(one_signature);
    BOOST_CHECK(one_signature[2].empty());
    BOOST_CHECK(!Consensus::CheckPolicySpendOf<Consensus::MlDsa44Kind>(2, hashes, one_signature, sighash));

    std::vector<std::vector<unsigned char>> two_signatures;
    AppendSigned(two_signatures, holders[0], sighash);
    AppendSigned(two_signatures, holders[1], sighash);
    AppendSkipped(two_signatures);
    BOOST_CHECK(two_signatures.back().empty());
    BOOST_CHECK(Consensus::CheckPolicySpendOf<Consensus::MlDsa44Kind>(2, hashes, two_signatures, sighash));

    std::vector<std::vector<unsigned char>> extra{two_signatures};
    extra.push_back({0x00});
    BOOST_CHECK(!Consensus::CheckPolicySpendOf<Consensus::MlDsa44Kind>(2, hashes, extra, sighash));

    const auto outsider{MakeHolder(9)};
    std::vector<std::vector<unsigned char>> other_keys;
    AppendSigned(other_keys, holders[0], sighash);
    AppendSigned(other_keys, holders[1], sighash);
    AppendSigned(other_keys, outsider, sighash);
    BOOST_CHECK(!Consensus::CheckPolicySpendOf<Consensus::MlDsa44Kind>(2, hashes, other_keys, sighash));
}

BOOST_AUTO_TEST_SUITE_END()
