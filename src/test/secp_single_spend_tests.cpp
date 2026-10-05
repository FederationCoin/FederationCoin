// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/secp_spend.h>
#include <hash.h>
#include <key.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <array>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(secp_single_spend_tests, BasicTestingSetup)

static CKey MakeKey()
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    return key;
}

BOOST_AUTO_TEST_CASE(single_key_accepted)
{
    const CKey key{MakeKey()};
    const CPubKey pub{key.GetPubKey()};
    const uint160 program{Hash160(pub)};
    const uint256 sighash{uint256::ONE};
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(sighash, signature));
    signature.push_back(SIGHASH_ALL | SIGHASH_UNIFIED);

    std::vector<std::vector<unsigned char>> witness;
    witness.push_back(signature);
    witness.emplace_back(pub.begin(), pub.end());
    BOOST_CHECK(Consensus::CheckSecpSingleKeySpend(program, witness, {sighash.begin(), sighash.size()}));
}

BOOST_AUTO_TEST_CASE(p2wsh_and_extra_item_rejected)
{
    const CKey key{MakeKey()};
    const CPubKey pub{key.GetPubKey()};
    const uint160 program{Hash160(pub)};
    const uint256 sighash{uint256::ONE};
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(sighash, signature));
    signature.push_back(SIGHASH_ALL | SIGHASH_UNIFIED);

    std::vector<std::vector<unsigned char>> extra;
    extra.push_back(signature);
    extra.emplace_back(pub.begin(), pub.end());
    extra.push_back({0x50});
    BOOST_CHECK(!Consensus::CheckSecpSingleKeySpend(program, extra, {sighash.begin(), sighash.size()}));

    std::vector<std::vector<unsigned char>> p2wsh;
    p2wsh.push_back({OP_TRUE});
    BOOST_CHECK(!Consensus::CheckSecpSingleKeySpend(program, p2wsh, {sighash.begin(), sighash.size()}));

    uint160 other;
    other.SetNull();
    BOOST_CHECK(!Consensus::CheckSecpSingleKeySpend(other, extra, {sighash.begin(), sighash.size()}));
}

static std::vector<unsigned char> PadS(const std::vector<unsigned char>& sig_with_ht)
{
    BOOST_REQUIRE(sig_with_ht.size() >= 9);
    const unsigned char hashtype{sig_with_ht.back()};
    std::vector<unsigned char> sig{sig_with_ht.begin(), sig_with_ht.end() - 1};
    BOOST_REQUIRE_EQUAL(sig[0], 0x30);
    const unsigned int len_r{sig[3]};
    const unsigned int len_s{sig[5 + len_r]};
    const size_t s_start{6 + len_r};
    std::vector<unsigned char> padded;
    padded.push_back(0x30);
    padded.push_back(static_cast<unsigned char>(sig[1] + 1));
    padded.insert(padded.end(), sig.begin() + 2, sig.begin() + s_start);
    padded.back() = static_cast<unsigned char>(len_s + 1);
    padded.push_back(0x00);
    padded.insert(padded.end(), sig.begin() + s_start, sig.end());
    padded.push_back(hashtype);
    return padded;
}

BOOST_AUTO_TEST_CASE(padded_s_rejected)
{
    const CKey key{MakeKey()};
    const CPubKey pub{key.GetPubKey()};
    const uint160 program{Hash160(pub)};
    const uint256 sighash{uint256::ONE};
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(sighash, signature));
    signature.push_back(SIGHASH_ALL | SIGHASH_UNIFIED);

    std::vector<std::vector<unsigned char>> canonical;
    canonical.push_back(signature);
    canonical.emplace_back(pub.begin(), pub.end());
    BOOST_CHECK(Consensus::CheckSecpSingleKeySpend(program, canonical, {sighash.begin(), sighash.size()}));

    std::vector<std::vector<unsigned char>> padded;
    padded.push_back(PadS(signature));
    padded.emplace_back(pub.begin(), pub.end());
    BOOST_CHECK(!Consensus::CheckSecpSingleKeySpend(program, padded, {sighash.begin(), sighash.size()}));
}

BOOST_AUTO_TEST_SUITE_END()
