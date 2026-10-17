// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa87_spend.h>
#include <consensus/mldsa44_spend.h>
#include <test/util/setup_common.h>

#include <array>
#include <algorithm>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mldsa87_multisig_tests, BasicTestingSetup)

struct Holder87 {
    Consensus::MlDsa87Keypair key;
    uint256 hash;
};

static Holder87 MakeHolder(unsigned char mark)
{
    std::array<unsigned char, Consensus::MLDSA87_SEED_SIZE> seed{};
    seed.fill(mark);
    Holder87 holder;
    BOOST_REQUIRE(Consensus::MlDsa87Keygen(seed, holder.key));
    holder.hash = Consensus::MlDsa87KeyHash(holder.key.pubkey);
    return holder;
}

static void AppendSigned(std::vector<std::vector<unsigned char>>& witness, const Holder87& holder, std::span<const unsigned char> sighash)
{
    std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE> signature{};
    BOOST_REQUIRE(Consensus::MlDsa87Sign(holder.key, sighash, signature));
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
    std::vector<Holder87> holders;
    holders.push_back(MakeHolder(1));
    holders.push_back(MakeHolder(2));
    holders.push_back(MakeHolder(3));
    std::sort(holders.begin(), holders.end(), [](const Holder87& a, const Holder87& b) { return a.hash < b.hash; });

    const std::array<uint256, 3> hashes{holders[0].hash, holders[1].hash, holders[2].hash};
    const auto program{Consensus::MlDsa87PolicyProgram(2, hashes)};
    BOOST_REQUIRE(program.has_value());

    const std::array<unsigned char, 32> sighash{4};

    std::vector<std::vector<unsigned char>> one_signature;
    AppendSigned(one_signature, holders[0], sighash);
    AppendSkipped(one_signature);
    AppendSkipped(one_signature);
    BOOST_CHECK(!Consensus::CheckMultisig87Spend(2, hashes, one_signature, sighash));

    std::vector<std::vector<unsigned char>> two_signatures;
    AppendSigned(two_signatures, holders[0], sighash);
    AppendSigned(two_signatures, holders[1], sighash);
    AppendSkipped(two_signatures);
    BOOST_CHECK(Consensus::CheckMultisig87Spend(2, hashes, two_signatures, sighash));
}

BOOST_AUTO_TEST_CASE(mixed_44_87_policy_rejected)
{
    std::array<unsigned char, Consensus::MLDSA44_SEED_SIZE> seed44{};
    seed44[0] = 8;
    Consensus::MlDsa44Keypair key44;
    BOOST_REQUIRE(Consensus::MlDsa44Keygen(seed44, key44));
    const Holder87 holder87{MakeHolder(9)};
    uint256 h44{Consensus::MlDsa44KeyHash(key44.pubkey)};
    uint256 h87{holder87.hash};
    if (!(h44 < h87)) std::swap(h44, h87);
    const std::array<uint256, 2> mixed{h44, h87};
    const auto program{Consensus::MlDsa87PolicyProgram(2, mixed)};
    BOOST_REQUIRE(program.has_value());

    const std::array<unsigned char, 32> sighash{5};
    std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> sig44{};
    BOOST_REQUIRE(Consensus::MlDsa44Sign(key44, sighash, sig44));
    std::vector<unsigned char> item44(key44.pubkey.begin(), key44.pubkey.end());
    item44.insert(item44.end(), sig44.begin(), sig44.end());
    std::vector<std::vector<unsigned char>> witness;
    if (Consensus::MlDsa44KeyHash(key44.pubkey) < holder87.hash) {
        witness.push_back(std::move(item44));
        AppendSigned(witness, holder87, sighash);
    } else {
        AppendSigned(witness, holder87, sighash);
        witness.push_back(std::move(item44));
    }
    BOOST_CHECK(!Consensus::CheckMultisig87Spend(2, mixed, witness, sighash));
    BOOST_CHECK(!Consensus::CheckPolicySpendOf<Consensus::MlDsa44Kind>(2, mixed, witness, sighash));
}

BOOST_AUTO_TEST_SUITE_END()
