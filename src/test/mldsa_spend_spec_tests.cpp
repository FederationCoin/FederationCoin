// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/federation_spend_vectors.json.h>

#include <consensus/consensus.h>
#include <consensus/mldsa44_spend.h>
#include <consensus/mldsa87_spend.h>
#include <consensus/mldsa_seed.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <key.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/mldsa_merge.h>
#include <script/modern_sig.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/transaction_identifier.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <span>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mldsa_spend_spec_tests, BasicTestingSetup)

static UniValue LoadVectors()
{
    UniValue v;
    BOOST_REQUIRE(v.read(json_tests::federation_spend_vectors));
    BOOST_REQUIRE(v.isObject());
    return v;
}

static uint256 HashFromHex(const std::string& hex)
{
    const std::vector<unsigned char> raw{ParseHex(hex)};
    BOOST_REQUIRE_EQUAL(raw.size(), 32U);
    return uint256{Span<const unsigned char>{raw.data(), raw.size()}};
}

static std::vector<unsigned char> BytesFromHex(const std::string& hex)
{
    return ParseHex(hex);
}

static std::array<unsigned char, 32> SeedFromHex(const std::string& hex)
{
    const std::vector<unsigned char> raw{ParseHex(hex)};
    BOOST_REQUIRE_EQUAL(raw.size(), 32U);
    std::array<unsigned char, 32> seed{};
    std::copy(raw.begin(), raw.end(), seed.begin());
    return seed;
}

static std::vector<unsigned char> Concat44(const Consensus::MlDsa44Keypair& key, std::span<const unsigned char> signature)
{
    std::vector<unsigned char> item(key.pubkey.begin(), key.pubkey.end());
    item.insert(item.end(), signature.begin(), signature.end());
    return item;
}

static std::vector<unsigned char> Concat87(const Consensus::MlDsa87Keypair& key, std::span<const unsigned char> signature)
{
    std::vector<unsigned char> item(key.pubkey.begin(), key.pubkey.end());
    item.insert(item.end(), signature.begin(), signature.end());
    return item;
}

struct Holder44 {
    Consensus::MlDsa44Keypair key;
    uint256 hash;
};

struct Holder87 {
    Consensus::MlDsa87Keypair key;
    uint256 hash;
};

static Holder44 MakeHolder44(unsigned char mark)
{
    std::array<unsigned char, Consensus::MLDSA44_SEED_SIZE> seed{};
    seed.fill(mark);
    Holder44 holder;
    BOOST_REQUIRE(Consensus::MlDsa44Keygen(seed, holder.key));
    holder.hash = Consensus::MlDsa44KeyHash(holder.key.pubkey);
    return holder;
}

static Holder87 MakeHolder87(unsigned char mark)
{
    std::array<unsigned char, Consensus::MLDSA87_SEED_SIZE> seed{};
    seed.fill(mark);
    Holder87 holder;
    BOOST_REQUIRE(Consensus::MlDsa87Keygen(seed, holder.key));
    holder.hash = Consensus::MlDsa87KeyHash(holder.key.pubkey);
    return holder;
}

static void AppendSigned44(std::vector<std::vector<unsigned char>>& witness, const Holder44& holder, std::span<const unsigned char> sighash)
{
    std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> signature{};
    BOOST_REQUIRE(Consensus::MlDsa44Sign(holder.key, sighash, signature));
    witness.push_back(Concat44(holder.key, signature));
}

static void AppendSkipped(std::vector<std::vector<unsigned char>>& witness)
{
    witness.emplace_back();
}

static void AppendSigned87(std::vector<std::vector<unsigned char>>& witness, const Holder87& holder, std::span<const unsigned char> sighash)
{
    std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE> signature{};
    BOOST_REQUIRE(Consensus::MlDsa87Sign(holder.key, sighash, signature));
    witness.push_back(Concat87(holder.key, signature));
}

static bool ScriptCheckFails(const CScript& spk, const std::vector<std::vector<unsigned char>>& witness, const CScript& script_sig = CScript{})
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vin[0].scriptSig = script_sig;
    tx.vin[0].scriptWitness.stack = witness;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1;
    tx.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(WITNESS_V0_KEYHASH_SIZE, 0x03);

    CTxOut spent;
    spent.nValue = 1;
    spent.scriptPubKey = spk;

    const CTransaction ctx{tx};
    PrecomputedTransactionData txdata;
    txdata.Init(ctx, {spent}, /*force=*/true);
    CScriptCheck check(spent, ctx, 0, &txdata);
    const auto err{check()};
    return err.has_value();
}

BOOST_AUTO_TEST_CASE(frozen_single_and_policy_programs)
{
    const UniValue vec{LoadVectors()};
    const UniValue& s44{vec["single44"]};
    const auto seed44{SeedFromHex(s44["seed"].get_str())};
    Consensus::MlDsa44Keypair key44;
    BOOST_REQUIRE(Consensus::MlDsa44Keygen(seed44, key44));
    BOOST_CHECK(Consensus::MlDsa44SingleKeyProgram(key44.pubkey) == HashFromHex(s44["program"].get_str()));
    BOOST_CHECK(Consensus::MlDsa44KeyHash(key44.pubkey) == HashFromHex(s44["program"].get_str()));
    const std::array<uint256, 1> one44{Consensus::MlDsa44KeyHash(key44.pubkey)};
    BOOST_CHECK_EQUAL(HexStr(*Consensus::MlDsa44PolicyProgram(1, one44)), s44["policy_1of1_scriptPubKey"].get_str());
    BOOST_CHECK_EQUAL(HexStr(BuildModernSingle(HashFromHex(s44["program"].get_str()), ALGO_DILITHIUM, PARAM_DILITHIUM_44)), s44["scriptPubKey"].get_str());
    BOOST_CHECK(s44["scriptPubKey"].get_str() != s44["policy_1of1_scriptPubKey"].get_str());

    const std::vector<unsigned char> pubkey44{BytesFromHex(s44["pubkey"].get_str())};
    const std::vector<unsigned char> sig44{BytesFromHex(s44["signature"].get_str())};
    BOOST_REQUIRE_EQUAL(pubkey44.size(), Consensus::MLDSA44_PUBLIC_KEY_SIZE);
    BOOST_REQUIRE_EQUAL(sig44.size(), Consensus::MLDSA44_SIGNATURE_SIZE);
    const auto sighash44{BytesFromHex(s44["sighash"].get_str())};
    std::vector<std::vector<unsigned char>> w44{pubkey44, sig44};
    std::vector<unsigned char> policy_item44{pubkey44};
    policy_item44.insert(policy_item44.end(), sig44.begin(), sig44.end());
    std::vector<std::vector<unsigned char>> policy_w44{policy_item44};
    BOOST_CHECK(Consensus::CheckSingleKey44Spend(HashFromHex(s44["program"].get_str()), w44, sighash44));
    BOOST_CHECK(!Consensus::CheckPolicySpendOf<Consensus::MlDsa44Kind>(1, one44, w44, sighash44));
    BOOST_CHECK(Consensus::CheckMultisig44Spend(1, one44, policy_w44, sighash44));
    BOOST_CHECK(!Consensus::CheckSingleKey44Spend(HashFromHex(s44["program"].get_str()), policy_w44, sighash44));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(w44) == Consensus::MlDsa44WitnessLayout::Single);
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(policy_w44) == Consensus::MlDsa44WitnessLayout::Policy);

    const UniValue& s87{vec["single87"]};
    const auto seed87{SeedFromHex(s87["seed"].get_str())};
    Consensus::MlDsa87Keypair key87;
    BOOST_REQUIRE(Consensus::MlDsa87Keygen(seed87, key87));
    BOOST_CHECK(Consensus::MlDsa87SingleKeyProgram(key87.pubkey) == HashFromHex(s87["program"].get_str()));
    const std::array<uint256, 1> one87{Consensus::MlDsa87KeyHash(key87.pubkey)};
    BOOST_CHECK_EQUAL(HexStr(*Consensus::MlDsa87PolicyProgram(1, one87)), s87["policy_1of1_scriptPubKey"].get_str());
    BOOST_CHECK_EQUAL(HexStr(BuildModernSingle(HashFromHex(s87["program"].get_str()), ALGO_DILITHIUM, PARAM_DILITHIUM_87)), s87["scriptPubKey"].get_str());
    const std::vector<unsigned char> pubkey87{BytesFromHex(s87["pubkey"].get_str())};
    const std::vector<unsigned char> sig87{BytesFromHex(s87["signature"].get_str())};
    const auto sighash87{BytesFromHex(s87["sighash"].get_str())};
    std::vector<std::vector<unsigned char>> w87{pubkey87, sig87};
    BOOST_CHECK(Consensus::CheckSingleKey87Spend(HashFromHex(s87["program"].get_str()), w87, sighash87));
    BOOST_CHECK(!Consensus::CheckSingleKey44Spend(HashFromHex(s87["program"].get_str()), w87, sighash87));
    BOOST_CHECK(Consensus::ClassifyMlDsa87Witness(w87) == Consensus::MlDsa87WitnessLayout::Single);

    const UniValue& p44{vec["policy44_2of3"]};
    std::vector<uint256> hashes44;
    const UniValue& hashes44_json{p44["hashes_sorted"].get_array()};
    for (size_t i{0}; i < hashes44_json.size(); ++i) {
        hashes44.push_back(HashFromHex(hashes44_json[i].get_str()));
    }
    BOOST_CHECK_EQUAL(HexStr(*Consensus::MlDsa44PolicyProgram(2, hashes44)), p44["scriptPubKey"].get_str());
    BOOST_CHECK_EQUAL(HexStr(*Consensus::MlDsa44PolicyProgram(1, hashes44)), p44["scriptPubKey_t1"].get_str());
    BOOST_CHECK_EQUAL(HexStr(*Consensus::MlDsa44PolicyProgram(3, hashes44)), p44["scriptPubKey_t3"].get_str());

    const UniValue& p87{vec["policy87_2of3"]};
    std::vector<uint256> hashes87;
    const UniValue& hashes87_json{p87["hashes_sorted"].get_array()};
    for (size_t i{0}; i < hashes87_json.size(); ++i) {
        hashes87.push_back(HashFromHex(hashes87_json[i].get_str()));
    }
    BOOST_CHECK_EQUAL(HexStr(*Consensus::MlDsa87PolicyProgram(2, hashes87)), p87["scriptPubKey"].get_str());
}

BOOST_AUTO_TEST_CASE(policy_bounds_and_sort)
{
    BOOST_CHECK(!Consensus::MlDsa44PolicyProgram(1, std::span<const uint256>{}));
    BOOST_CHECK(!Consensus::MlDsa87PolicyProgram(1, std::span<const uint256>{}));

    std::vector<uint256> thirteen(13);
    for (std::size_t i{0}; i < thirteen.size(); ++i) {
        std::vector<unsigned char> raw(32, 0);
        raw.back() = static_cast<unsigned char>(i + 1);
        thirteen[i] = uint256{Span<const unsigned char>{raw.data(), raw.size()}};
    }
    BOOST_CHECK(!Consensus::MlDsa44PolicyProgram(1, thirteen));
    BOOST_CHECK(!Consensus::MlDsa87PolicyProgram(1, thirteen));

    const std::array<uint256, 2> two{thirteen[0], thirteen[1]};
    BOOST_CHECK(!Consensus::MlDsa44PolicyProgram(3, two));
    BOOST_CHECK(Consensus::MlDsa44PolicyProgram(2, two).has_value());

    const std::array<uint256, 2> dup{thirteen[0], thirteen[0]};
    BOOST_CHECK(!Consensus::MlDsa44PolicyProgram(1, dup));

    const UniValue vec{LoadVectors()};
    const UniValue& hx{vec["hex_display_sort"]};
    const uint256 h_lo{HashFromHex(hx["h_lo"].get_str())};
    const uint256 h_hi{HashFromHex(hx["h_hi"].get_str())};
    BOOST_CHECK(h_lo < h_hi);
    BOOST_CHECK(h_hi.GetHex() < h_lo.GetHex());
    const std::array<uint256, 2> byte_order{h_lo, h_hi};
    const std::array<uint256, 2> gethex_order{h_hi, h_lo};
    BOOST_CHECK_EQUAL(HexStr(*Consensus::MlDsa44PolicyProgram(2, byte_order)), hx["scriptPubKey_after_uint256_sort"].get_str());
    BOOST_CHECK_EQUAL(HexStr(*Consensus::MlDsa44PolicyProgram(2, gethex_order)), hx["scriptPubKey_after_uint256_sort"].get_str());
    BOOST_CHECK(hx["scriptPubKey_after_uint256_sort"].get_str() != hx["scriptPubKey_gethex_order"].get_str());
}

BOOST_AUTO_TEST_CASE(policy_slots_44)
{
    std::vector<Holder44> holders;
    holders.push_back(MakeHolder44(1));
    holders.push_back(MakeHolder44(2));
    holders.push_back(MakeHolder44(3));
    std::sort(holders.begin(), holders.end(), [](const Holder44& a, const Holder44& b) { return a.hash < b.hash; });
    const std::array<uint256, 3> hashes{holders[0].hash, holders[1].hash, holders[2].hash};
    const auto program{Consensus::MlDsa44PolicyProgram(2, hashes)};
    BOOST_REQUIRE(program);
    const std::array<unsigned char, 32> sighash{4};

    std::vector<std::vector<unsigned char>> two_sig;
    AppendSigned44(two_sig, holders[0], sighash);
    AppendSigned44(two_sig, holders[1], sighash);
    AppendSkipped(two_sig);
    BOOST_CHECK(Consensus::CheckMultisig44Spend(2, hashes, two_sig, sighash));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(two_sig) == Consensus::MlDsa44WitnessLayout::Policy);

    std::vector<std::vector<unsigned char>> unsorted;
    AppendSigned44(unsorted, holders[1], sighash);
    AppendSigned44(unsorted, holders[0], sighash);
    AppendSkipped(unsorted);
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(2, hashes, unsorted, sighash));

    std::vector<std::vector<unsigned char>> all_skip;
    AppendSkipped(all_skip);
    AppendSkipped(all_skip);
    AppendSkipped(all_skip);
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(2, hashes, all_skip, sighash));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(all_skip) == Consensus::MlDsa44WitnessLayout::Policy);

    std::vector<std::vector<unsigned char>> all_signed;
    AppendSigned44(all_signed, holders[0], sighash);
    AppendSigned44(all_signed, holders[1], sighash);
    AppendSigned44(all_signed, holders[2], sighash);
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(2, hashes, all_signed, sighash));

    std::vector<std::vector<unsigned char>> truncated;
    truncated.emplace_back(holders[0].key.pubkey.begin(), holders[0].key.pubkey.end());
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(2, hashes, truncated, sighash));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(truncated) == Consensus::MlDsa44WitnessLayout::Neither);

    std::vector<std::vector<unsigned char>> mid_skip_in_pair;
    mid_skip_in_pair.emplace_back(holders[0].key.pubkey.begin(), holders[0].key.pubkey.end());
    AppendSkipped(mid_skip_in_pair);
    std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> sig{};
    BOOST_REQUIRE(Consensus::MlDsa44Sign(holders[0].key, sighash, sig));
    mid_skip_in_pair.emplace_back(sig.begin(), sig.end());
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(2, hashes, mid_skip_in_pair, sighash));

    BOOST_CHECK(!Consensus::CheckMultisig44Spend(2, hashes, {}, sighash));
    std::vector<std::vector<unsigned char>> thirteen(13);
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(2, hashes, thirteen, sighash));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness({}) == Consensus::MlDsa44WitnessLayout::Neither);
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(thirteen) == Consensus::MlDsa44WitnessLayout::Neither);
}

BOOST_AUTO_TEST_CASE(policy_slots_87_and_no_mix)
{
    std::vector<Holder87> holders;
    holders.push_back(MakeHolder87(1));
    holders.push_back(MakeHolder87(2));
    holders.push_back(MakeHolder87(3));
    std::sort(holders.begin(), holders.end(), [](const Holder87& a, const Holder87& b) { return a.hash < b.hash; });
    const std::array<uint256, 3> hashes{holders[0].hash, holders[1].hash, holders[2].hash};
    const auto program{Consensus::MlDsa87PolicyProgram(2, hashes)};
    BOOST_REQUIRE(program);
    const std::array<unsigned char, 32> sighash{4};

    std::vector<std::vector<unsigned char>> two_sig;
    AppendSigned87(two_sig, holders[0], sighash);
    AppendSigned87(two_sig, holders[1], sighash);
    AppendSkipped(two_sig);
    BOOST_CHECK(Consensus::CheckMultisig87Spend(2, hashes, two_sig, sighash));
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(2, hashes, two_sig, sighash));

    const Holder44 outsider{MakeHolder44(8)};
    std::vector<std::vector<unsigned char>> mixed;
    AppendSigned44(mixed, outsider, sighash);
    AppendSigned87(mixed, holders[1], sighash);
    AppendSkipped(mixed);
    BOOST_CHECK(!Consensus::CheckMultisig87Spend(2, hashes, mixed, sighash));
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(2, hashes, mixed, sighash));

    const std::array<uint256, 1> one44{outsider.hash};
    const auto program44{Consensus::MlDsa44PolicyProgram(1, one44)};
    BOOST_REQUIRE(program44);
    BOOST_CHECK(!Consensus::CheckMultisig87Spend(1, one44, two_sig, sighash));
}

BOOST_AUTO_TEST_CASE(merge_87_and_fail_closed_without_sighash)
{
    std::vector<Holder87> holders;
    holders.push_back(MakeHolder87(1));
    holders.push_back(MakeHolder87(2));
    std::sort(holders.begin(), holders.end(), [](const Holder87& a, const Holder87& b) { return a.hash < b.hash; });
    const std::array<uint256, 2> hashes{holders[0].hash, holders[1].hash};
    const auto program{Consensus::MlDsa87PolicyProgram(2, hashes)};
    BOOST_REQUIRE(program);
    const std::array<unsigned char, 32> sighash{9};

    std::vector<std::vector<unsigned char>> partial_a;
    AppendSigned87(partial_a, holders[0], sighash);
    AppendSkipped(partial_a);
    std::vector<std::vector<unsigned char>> partial_b;
    AppendSkipped(partial_b);
    AppendSigned87(partial_b, holders[1], sighash);

    const auto merged{Consensus::MergeMlDsa87Witnesses({partial_a, partial_b}, sighash)};
    BOOST_REQUIRE(merged);
    BOOST_CHECK(Consensus::CheckMultisig87Spend(2, hashes, *merged, sighash));

    BOOST_CHECK(!Consensus::MergeMlDsa87Witnesses({partial_a, partial_b}, std::span<const unsigned char>{}));
    BOOST_CHECK(!Consensus::MergeMlDsa44Witnesses({partial_a, partial_b}, sighash));

    std::vector<std::vector<unsigned char>> other = partial_b;
    BOOST_REQUIRE(!other[1].empty());
    std::fill(other[1].begin(), other[1].end(), static_cast<unsigned char>(0x22));
    BOOST_CHECK(!Consensus::MergeMlDsa87Witnesses({partial_a, other}, sighash));
}

BOOST_AUTO_TEST_CASE(policy_matrix_44_and_87)
{
    const UniValue vec{LoadVectors()};
    const UniValue& hx{vec["hex_display_sort"]};
    const uint256 h_lo{HashFromHex(hx["h_lo"].get_str())};
    const uint256 h_hi{HashFromHex(hx["h_hi"].get_str())};
    const std::array<uint256, 2> gethex_order{h_hi, h_lo};
    BOOST_CHECK_EQUAL(HexStr(*Consensus::MlDsa44PolicyProgram(2, gethex_order)), hx["scriptPubKey_after_uint256_sort"].get_str());

    std::vector<uint256> twelve_hashes;
    twelve_hashes.reserve(12);
    for (int i{0}; i < 12; ++i) {
        std::vector<unsigned char> raw(32, 0);
        raw.back() = static_cast<unsigned char>(i + 1);
        twelve_hashes.emplace_back(Span<const unsigned char>{raw.data(), raw.size()});
    }
    BOOST_CHECK(Consensus::MlDsa44PolicyProgram(12, twelve_hashes).has_value());
    BOOST_CHECK(Consensus::MlDsa87PolicyProgram(12, twelve_hashes).has_value());
    BOOST_CHECK(Consensus::MlDsa44PolicyProgram(11, twelve_hashes).has_value());
    BOOST_CHECK(Consensus::MlDsa87PolicyProgram(11, twelve_hashes).has_value());
    BOOST_CHECK_LE((*Consensus::MlDsa44PolicyProgram(12, twelve_hashes)).size(), DILITHIUM_POLICY_SCRIPT_MAX);

    const std::array<unsigned char, 32> sighash{7};

    std::vector<Holder44> h44;
    h44.reserve(12);
    for (int i{0}; i < 12; ++i) {
        h44.push_back(MakeHolder44(static_cast<unsigned char>(i + 10)));
    }
    std::sort(h44.begin(), h44.end(), [](const Holder44& a, const Holder44& b) { return a.hash < b.hash; });

    auto hashes44 = [&](int n) {
        std::vector<uint256> out;
        out.reserve(n);
        for (int i{0}; i < n; ++i) out.push_back(h44[i].hash);
        return out;
    };
    auto wit44 = [&](int n, int signed_count) {
        std::vector<std::vector<unsigned char>> wit;
        for (int i{0}; i < n; ++i) {
            if (i < signed_count) AppendSigned44(wit, h44[i], sighash);
            else AppendSkipped(wit);
        }
        return wit;
    };

    const struct {
        int t;
        int n;
        int signed_ok;
        bool expect;
    } rows[] = {
        {1, 2, 1, true},
        {1, 2, 0, false},
        {2, 3, 2, true},
        {2, 3, 3, false},
        {2, 3, 1, false},
        {3, 5, 3, true},
        {3, 5, 4, false},
        {3, 5, 2, false},
        {11, 12, 11, true},
        {11, 12, 10, false},
        {12, 12, 12, true},
        {12, 12, 11, false},
    };
    for (const auto& row : rows) {
        const auto hashes{hashes44(row.n)};
        const auto program{Consensus::MlDsa44PolicyProgram(static_cast<uint8_t>(row.t), hashes)};
        BOOST_REQUIRE(program);
        BOOST_CHECK_EQUAL(Consensus::CheckMultisig44Spend(static_cast<uint8_t>(row.t), hashes, wit44(row.n, row.signed_ok), sighash), row.expect);
    }

    {
        const auto hashes{hashes44(2)};
        const auto program{Consensus::MlDsa44PolicyProgram(1, hashes)};
        BOOST_REQUIRE(program);
        auto dup = wit44(2, 1);
        AppendSkipped(dup);
        BOOST_CHECK(!Consensus::CheckMultisig44Spend(1, hashes, dup, sighash));
        auto extra = wit44(2, 2);
        AppendSkipped(extra);
        BOOST_CHECK(!Consensus::CheckMultisig44Spend(1, hashes, extra, sighash));
    }

    std::vector<Holder87> h87;
    h87.reserve(12);
    for (int i{0}; i < 12; ++i) {
        h87.push_back(MakeHolder87(static_cast<unsigned char>(i + 20)));
    }
    std::sort(h87.begin(), h87.end(), [](const Holder87& a, const Holder87& b) { return a.hash < b.hash; });

    auto hashes87 = [&](int n) {
        std::vector<uint256> out;
        out.reserve(n);
        for (int i{0}; i < n; ++i) out.push_back(h87[i].hash);
        return out;
    };
    auto wit87 = [&](int n, int signed_count) {
        std::vector<std::vector<unsigned char>> wit;
        for (int i{0}; i < n; ++i) {
            if (i < signed_count) AppendSigned87(wit, h87[i], sighash);
            else AppendSkipped(wit);
        }
        return wit;
    };
    for (const auto& row : rows) {
        const auto hashes{hashes87(row.n)};
        const auto program{Consensus::MlDsa87PolicyProgram(static_cast<uint8_t>(row.t), hashes)};
        BOOST_REQUIRE(program);
        BOOST_CHECK_EQUAL(Consensus::CheckMultisig87Spend(static_cast<uint8_t>(row.t), hashes, wit87(row.n, row.signed_ok), sighash), row.expect);
    }
    {
        const auto hashes{hashes87(2)};
        const auto program{Consensus::MlDsa87PolicyProgram(1, hashes)};
        BOOST_REQUIRE(program);
        auto dup = wit87(2, 1);
        AppendSkipped(dup);
        BOOST_CHECK(!Consensus::CheckMultisig87Spend(1, hashes, dup, sighash));
        auto extra = wit87(2, 2);
        AppendSkipped(extra);
        BOOST_CHECK(!Consensus::CheckMultisig87Spend(1, hashes, extra, sighash));
    }
}

static CTransaction TxWithScript(const CScript& script)
{
    CMutableTransaction created;
    created.vin.resize(1);
    created.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    created.vout.emplace_back(1, script);
    return CTransaction{created};
}

BOOST_AUTO_TEST_CASE(p2wsh_and_op_true_rejected)
{
    CScript op_true;
    op_true << OP_TRUE;
    BOOST_CHECK_LE(op_true.size(), MAX_OUTPUT_SCRIPT_SIZE);
    TxValidationState state;
    BOOST_CHECK(!Consensus::CheckOutputSizes(TxWithScript(op_true), state));
    CScript p2pkh;
    p2pkh << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x02) << OP_EQUALVERIFY << OP_CHECKSIG;
    state = {};
    BOOST_CHECK(!Consensus::CheckOutputSizes(TxWithScript(p2pkh), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vout-script");
    state = {};
    BOOST_CHECK(!Consensus::CheckOutputSizes(TxWithScript(CScript{}), state));
    const CScript v0_20{CScript() << OP_0 << std::vector<unsigned char>(WITNESS_V0_KEYHASH_SIZE, 0x03)};
    state = {};
    BOOST_CHECK(Consensus::CheckOutputSizes(TxWithScript(v0_20), state));
    CScript commitment;
    commitment.resize(38);
    commitment[0] = OP_RETURN;
    commitment[1] = 0x24;
    commitment[2] = 0xaa;
    commitment[3] = 0x21;
    commitment[4] = 0xa9;
    commitment[5] = 0xed;
    state = {};
    BOOST_CHECK(Consensus::CheckOutputSizes(TxWithScript(commitment), state));
    BOOST_CHECK(Consensus::IsWitnessCommitmentScript(commitment));
    BOOST_CHECK(!ScriptCheckFails(op_true, {}));
    BOOST_CHECK(ScriptCheckFails(op_true, {{0x51}}));

    uint256 burn;
    std::fill(burn.begin(), burn.end(), static_cast<unsigned char>(0x11));
    const CScript v0_32{CScript() << OP_0 << std::vector<unsigned char>(burn.begin(), burn.end())};
    BOOST_CHECK_EQUAL(v0_32.size(), 34U);
    state = {};
    BOOST_CHECK(!Consensus::CheckOutputSizes(TxWithScript(v0_32), state));
    std::vector<std::vector<unsigned char>> p2wsh;
    p2wsh.push_back({OP_TRUE});
    BOOST_CHECK(ScriptCheckFails(v0_32, p2wsh));
    std::vector<std::vector<unsigned char>> p2wsh_dump;
    p2wsh_dump.push_back(std::vector<unsigned char>(80, 0xaa));
    p2wsh_dump.push_back({OP_TRUE});
    BOOST_CHECK(ScriptCheckFails(v0_32, p2wsh_dump));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(p2wsh_dump) == Consensus::MlDsa44WitnessLayout::Neither);
    BOOST_CHECK(Consensus::ClassifyMlDsa87Witness(p2wsh_dump) == Consensus::MlDsa87WitnessLayout::Neither);

    std::vector<uint256> twelve_hashes;
    twelve_hashes.reserve(12);
    for (int i{0}; i < 12; ++i) {
        std::vector<unsigned char> raw(32, 0);
        raw.back() = static_cast<unsigned char>(i + 1);
        twelve_hashes.emplace_back(Span<const unsigned char>{raw.data(), raw.size()});
    }
    const CScript policy12{*Consensus::MlDsa44PolicyProgram(12, twelve_hashes)};
    BOOST_CHECK_LE(policy12.size(), DILITHIUM_POLICY_SCRIPT_MAX);
    state = {};
    BOOST_CHECK(Consensus::CheckOutputSizes(TxWithScript(policy12), state));
    const CScript single{BuildModernSingle(twelve_hashes[0], ALGO_DILITHIUM, PARAM_DILITHIUM_44)};
    BOOST_CHECK_EQUAL(single.size(), DILITHIUM_SINGLE_SCRIPT_SIZE);
    state = {};
    BOOST_CHECK(Consensus::CheckOutputSizes(TxWithScript(single), state));
}

BOOST_AUTO_TEST_CASE(unknown_pair_pushdata_and_scriptsig)
{
    const UniValue vec{LoadVectors()};
    const UniValue& s44{vec["single44"]};
    const std::vector<unsigned char> unknown_raw{BytesFromHex(vec["unknown_pair"]["scriptPubKey"].get_str())};
    const CScript unknown{unknown_raw.begin(), unknown_raw.end()};
    BOOST_REQUIRE(MatchModernSingle(unknown));
    BOOST_CHECK(MatchModernSingle(unknown)->kind == nullptr);
    const std::vector<unsigned char> pubkey44{BytesFromHex(s44["pubkey"].get_str())};
    const std::vector<unsigned char> sig44{BytesFromHex(s44["signature"].get_str())};
    std::vector<std::vector<unsigned char>> w44{pubkey44, sig44};
    BOOST_CHECK(ScriptCheckFails(unknown, w44));
    BOOST_CHECK(!IsKnownModernSigTemplate(unknown));
    BOOST_CHECK(EncodeDestination(ModernSigDestination(unknown)).empty());

    const uint256 program{HashFromHex(s44["program"].get_str())};
    std::vector<unsigned char> pushdata;
    pushdata.push_back(OP_PUSHDATA1);
    pushdata.push_back(32);
    pushdata.insert(pushdata.end(), program.begin(), program.end());
    pushdata.push_back(OP_1);
    pushdata.push_back(OP_1);
    pushdata.push_back(OP_CHECKMODERNSIG);
    const CScript pushdata_spk{pushdata.begin(), pushdata.end()};
    BOOST_CHECK(!MatchModernSingle(pushdata_spk));
    BOOST_CHECK(ScriptCheckFails(pushdata_spk, w44));

    const CScript good{BuildModernSingle(program, ALGO_DILITHIUM, PARAM_DILITHIUM_44)};
    BOOST_CHECK(ScriptCheckFails(good, w44, CScript() << OP_0));
}

BOOST_AUTO_TEST_CASE(tagged_kdf_is_mldsa_seed)
{
    std::array<std::byte, 32> master_seed{};
    master_seed[0] = std::byte{0x0b};
    CExtKey master;
    master.SetSeed(master_seed);
    CExtKey account, chain, child;
    BOOST_REQUIRE(master.Derive(account, 0x80000000));
    BOOST_REQUIRE(account.Derive(chain, 0x80000000));
    BOOST_REQUIRE(chain.Derive(child, 0x80000000));
    BOOST_REQUIRE_EQUAL(child.key.size(), 32U);

    const std::span<const unsigned char> hd{
        reinterpret_cast<const unsigned char*>(master_seed.data()), master_seed.size()};
    std::array<unsigned char, Consensus::MLDSA_DERIVED_SEED_SIZE> derived44{};
    std::array<unsigned char, Consensus::MLDSA_DERIVED_SEED_SIZE> derived87{};
    BOOST_REQUIRE(Consensus::DeriveMlDsaSeed(hd, Consensus::MlDsaSeedKind::Dilithium44, 0, derived44));
    BOOST_REQUIRE(Consensus::DeriveMlDsaSeed(hd, Consensus::MlDsaSeedKind::Dilithium87, 0, derived87));
    BOOST_CHECK(derived44 != derived87);
    BOOST_CHECK(HexStr(Span{UCharCast(child.key.begin()), child.key.size()}) != HexStr(derived44));
    BOOST_CHECK_EQUAL(HexStr(Span{UCharCast(child.key.begin()), child.key.size()}),
                      "e1d174161b4abbe62bc2f998c79e8cf32d4b03f2d6f412b722645ad052c3061d");

    Consensus::MlDsa44Keypair k44;
    BOOST_REQUIRE(Consensus::MlDsa44Keygen(derived44, k44));
    Consensus::MlDsa87Keypair k87;
    BOOST_REQUIRE(Consensus::MlDsa87Keygen(derived87, k87));
    BOOST_CHECK(Consensus::MlDsa44SingleKeyProgram(k44.pubkey) != Consensus::MlDsa87SingleKeyProgram(k87.pubkey));
}

BOOST_AUTO_TEST_CASE(verify_script_policy_exact_t)
{
    std::vector<Holder44> holders;
    holders.push_back(MakeHolder44(1));
    holders.push_back(MakeHolder44(2));
    holders.push_back(MakeHolder44(3));
    std::sort(holders.begin(), holders.end(), [](const Holder44& a, const Holder44& b) { return a.hash < b.hash; });
    const std::array<uint256, 3> hashes{holders[0].hash, holders[1].hash, holders[2].hash};
    const auto program{Consensus::MlDsa44PolicyProgram(2, hashes)};
    BOOST_REQUIRE(program);

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1;
    tx.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(WITNESS_V0_KEYHASH_SIZE, 0x03);

    CTxOut spent{1, *program};
    const CTransaction unsigned_tx{tx};
    PrecomputedTransactionData txdata;
    txdata.Init(unsigned_tx, {spent}, /*force=*/true);
    TransactionSignatureChecker checker(&unsigned_tx, 0, spent.nValue, txdata, MissingDataBehavior::ASSERT_FAIL);
    uint256 sighash;
    BOOST_REQUIRE(checker.GetUnifiedSighash(sighash));
    std::array<unsigned char, 32> msg{};
    std::copy(sighash.begin(), sighash.end(), msg.begin());

    std::vector<std::vector<unsigned char>> exact;
    AppendSigned44(exact, holders[0], msg);
    AppendSigned44(exact, holders[1], msg);
    AppendSkipped(exact);
    BOOST_CHECK(!ScriptCheckFails(*program, exact));

    std::vector<std::vector<unsigned char>> extra;
    AppendSigned44(extra, holders[0], msg);
    AppendSigned44(extra, holders[1], msg);
    AppendSigned44(extra, holders[2], msg);
    BOOST_CHECK(ScriptCheckFails(*program, extra));

    std::vector<std::vector<unsigned char>> shortfall;
    AppendSigned44(shortfall, holders[0], msg);
    AppendSkipped(shortfall);
    AppendSkipped(shortfall);
    BOOST_CHECK(ScriptCheckFails(*program, shortfall));
}

BOOST_AUTO_TEST_CASE(unified_off_p2wsh_rejected)
{
    uint256 burn;
    std::fill(burn.begin(), burn.end(), static_cast<unsigned char>(0x11));
    const CScript v0_32{CScript() << OP_0 << std::vector<unsigned char>(burn.begin(), burn.end())};
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vin[0].scriptWitness.stack = {{OP_TRUE}};
    tx.vout.resize(1);
    tx.vout[0].nValue = 1;
    tx.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(WITNESS_V0_KEYHASH_SIZE, 0x03);
    CTxOut spent{1, v0_32};
    PrecomputedTransactionData txdata;
    txdata.Init(tx, {spent}, /*force=*/true);
    MutableTransactionSignatureChecker checker(&tx, 0, spent.nValue, txdata, MissingDataBehavior::FAIL);
    ScriptError err{SCRIPT_ERR_OK};
    const unsigned flags_no_unified{STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_UNIFIED_SIGHASH};
    BOOST_CHECK(!VerifyScript(CScript{}, v0_32, &tx.vin[0].scriptWitness, flags_no_unified, checker, &err));
}

BOOST_AUTO_TEST_SUITE_END()
