// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/secp_spend.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
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

static std::vector<unsigned char> NegateS(const std::vector<unsigned char>& sig_with_ht)
{
    BOOST_REQUIRE(sig_with_ht.size() >= 9);
    const unsigned char hashtype{sig_with_ht.back()};
    std::vector<unsigned char> vchSig{sig_with_ht.begin(), sig_with_ht.end() - 1};
    std::vector<unsigned char> r{vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]};
    std::vector<unsigned char> s{vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]};
    static const unsigned char order[33] = {
        0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
    while (s.size() < 33) {
        s.insert(s.begin(), 0x00);
    }
    int carry = 0;
    for (int p = 32; p >= 1; p--) {
        int n = static_cast<int>(order[p]) - s[p] - carry;
        s[p] = static_cast<unsigned char>((n + 256) & 0xFF);
        carry = (n < 0);
    }
    BOOST_REQUIRE_EQUAL(carry, 0);
    if (s.size() > 1 && s[0] == 0 && s[1] < 0x80) {
        s.erase(s.begin());
    }
    std::vector<unsigned char> out;
    out.push_back(0x30);
    out.push_back(static_cast<unsigned char>(4 + r.size() + s.size()));
    out.push_back(0x02);
    out.push_back(static_cast<unsigned char>(r.size()));
    out.insert(out.end(), r.begin(), r.end());
    out.push_back(0x02);
    out.push_back(static_cast<unsigned char>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
    out.push_back(hashtype);
    return out;
}

BOOST_AUTO_TEST_CASE(high_s_rejected)
{
    const CKey key{MakeKey()};
    const CPubKey pub{key.GetPubKey()};
    const uint160 program{Hash160(pub)};
    const uint256 sighash{uint256::ONE};
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(sighash, signature));
    signature.push_back(SIGHASH_ALL | SIGHASH_UNIFIED);

    std::vector<std::vector<unsigned char>> high;
    high.push_back(NegateS(signature));
    high.emplace_back(pub.begin(), pub.end());
    BOOST_CHECK(!Consensus::CheckSecpSingleKeySpend(program, high, {sighash.begin(), sighash.size()}));
}

BOOST_AUTO_TEST_CASE(unified_off_does_not_accept_p2wsh)
{
    CScript redeem;
    redeem << OP_TRUE;
    uint256 scripthash;
    CSHA256().Write(redeem.data(), redeem.size()).Finalize(scripthash.begin());
    CScript spk;
    spk << OP_0 << std::vector<unsigned char>(scripthash.begin(), scripthash.end());

    CScriptWitness wit;
    wit.stack.emplace_back();
    wit.stack.emplace_back(redeem.begin(), redeem.end());

    ScriptError err{SCRIPT_ERR_OK};
    const unsigned flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS};
    BOOST_CHECK(!VerifyScript(CScript(), spk, &wit, flags, DUMMY_CHECKER, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
}

BOOST_AUTO_TEST_SUITE_END()
