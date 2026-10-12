// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/federation_spend_vectors.json.h>

#include <consensus/consensus.h>
#include <consensus/mldsa44_spend.h>
#include <consensus/mldsa87_spend.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/mldsa_merge.h>
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
    witness.emplace_back(holder.key.pubkey.begin(), holder.key.pubkey.end());
    witness.emplace_back(signature.begin(), signature.end());
}

static void AppendSkipped(std::vector<std::vector<unsigned char>>& witness, const uint256& hash)
{
    witness.emplace_back(hash.begin(), hash.end());
}

static void AppendSigned87(std::vector<std::vector<unsigned char>>& witness, const Holder87& holder, std::span<const unsigned char> sighash)
{
    std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE> signature{};
    BOOST_REQUIRE(Consensus::MlDsa87Sign(holder.key, sighash, signature));
    witness.emplace_back(holder.key.pubkey.begin(), holder.key.pubkey.end());
    witness.emplace_back(signature.begin(), signature.end());
}

static bool ScriptCheckFails(const CScript& spk, const std::vector<std::vector<unsigned char>>& witness)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vin[0].scriptSig.clear();
    tx.vin[0].scriptWitness.stack = witness;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

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
    BOOST_CHECK(Consensus::MlDsa44PolicyProgram(1, one44) == HashFromHex(s44["policy_1of1_program"].get_str()));
    BOOST_CHECK(HashFromHex(s44["program"].get_str()) != HashFromHex(s44["policy_1of1_program"].get_str()));

    const std::vector<unsigned char> pubkey44{BytesFromHex(s44["pubkey"].get_str())};
    const std::vector<unsigned char> sig44{BytesFromHex(s44["signature"].get_str())};
    BOOST_REQUIRE_EQUAL(pubkey44.size(), Consensus::MLDSA44_PUBLIC_KEY_SIZE);
    BOOST_REQUIRE_EQUAL(sig44.size(), Consensus::MLDSA44_SIGNATURE_SIZE);
    const auto sighash44{BytesFromHex(s44["sighash"].get_str())};
    std::vector<std::vector<unsigned char>> w44{pubkey44, sig44};
    BOOST_CHECK(Consensus::CheckSingleKey44Spend(HashFromHex(s44["program"].get_str()), w44, sighash44));
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(HashFromHex(s44["program"].get_str()), w44, sighash44));
    BOOST_CHECK(Consensus::CheckMultisig44Spend(HashFromHex(s44["policy_1of1_program"].get_str()), w44, sighash44));
    BOOST_CHECK(!Consensus::CheckSingleKey44Spend(HashFromHex(s44["policy_1of1_program"].get_str()), w44, sighash44));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(w44) == Consensus::MlDsa44WitnessLayout::Single);

    const UniValue& s87{vec["single87"]};
    const auto seed87{SeedFromHex(s87["seed"].get_str())};
    Consensus::MlDsa87Keypair key87;
    BOOST_REQUIRE(Consensus::MlDsa87Keygen(seed87, key87));
    BOOST_CHECK(Consensus::MlDsa87SingleKeyProgram(key87.pubkey) == HashFromHex(s87["program"].get_str()));
    const std::array<uint256, 1> one87{Consensus::MlDsa87KeyHash(key87.pubkey)};
    BOOST_CHECK(Consensus::MlDsa87PolicyProgram(1, one87) == HashFromHex(s87["policy_1of1_program"].get_str()));
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
    BOOST_CHECK(Consensus::MlDsa44PolicyProgram(2, hashes44) == HashFromHex(p44["program"].get_str()));
    BOOST_CHECK(Consensus::MlDsa44PolicyProgram(1, hashes44) == HashFromHex(p44["program_t1"].get_str()));
    BOOST_CHECK(Consensus::MlDsa44PolicyProgram(3, hashes44) == HashFromHex(p44["program_t3"].get_str()));

    const UniValue& p87{vec["policy87_2of3"]};
    std::vector<uint256> hashes87;
    const UniValue& hashes87_json{p87["hashes_sorted"].get_array()};
    for (size_t i{0}; i < hashes87_json.size(); ++i) {
        hashes87.push_back(HashFromHex(hashes87_json[i].get_str()));
    }
    BOOST_CHECK(Consensus::MlDsa87PolicyProgram(2, hashes87) == HashFromHex(p87["program"].get_str()));
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
    BOOST_CHECK(Consensus::MlDsa44PolicyProgram(1, byte_order) == HashFromHex(hx["program_after_uint256_sort"].get_str()));
    BOOST_CHECK(Consensus::MlDsa44PolicyProgram(1, gethex_order) == HashFromHex(hx["program_after_uint256_sort"].get_str()));
    BOOST_CHECK(HashFromHex(hx["program_after_uint256_sort"].get_str()) != HashFromHex(hx["preimage_concat_gethex_order"].get_str()));
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
    AppendSkipped(two_sig, holders[2].hash);
    BOOST_CHECK(Consensus::CheckMultisig44Spend(*program, two_sig, sighash));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(two_sig) == Consensus::MlDsa44WitnessLayout::Policy);

    std::vector<std::vector<unsigned char>> unsorted;
    AppendSigned44(unsorted, holders[1], sighash);
    AppendSigned44(unsorted, holders[0], sighash);
    AppendSkipped(unsorted, holders[2].hash);
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(*program, unsorted, sighash));

    std::vector<std::vector<unsigned char>> all_skip;
    AppendSkipped(all_skip, holders[0].hash);
    AppendSkipped(all_skip, holders[1].hash);
    AppendSkipped(all_skip, holders[2].hash);
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(*program, all_skip, sighash));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(all_skip) == Consensus::MlDsa44WitnessLayout::Policy);

    std::vector<std::vector<unsigned char>> all_signed;
    AppendSigned44(all_signed, holders[0], sighash);
    AppendSigned44(all_signed, holders[1], sighash);
    AppendSigned44(all_signed, holders[2], sighash);
    BOOST_CHECK(Consensus::CheckMultisig44Spend(*program, all_signed, sighash));

    std::vector<std::vector<unsigned char>> truncated;
    truncated.emplace_back(holders[0].key.pubkey.begin(), holders[0].key.pubkey.end());
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(*program, truncated, sighash));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(truncated) == Consensus::MlDsa44WitnessLayout::Neither);

    std::vector<std::vector<unsigned char>> mid_skip_in_pair;
    mid_skip_in_pair.emplace_back(holders[0].key.pubkey.begin(), holders[0].key.pubkey.end());
    AppendSkipped(mid_skip_in_pair, holders[1].hash);
    std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> sig{};
    BOOST_REQUIRE(Consensus::MlDsa44Sign(holders[0].key, sighash, sig));
    mid_skip_in_pair.emplace_back(sig.begin(), sig.end());
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(*program, mid_skip_in_pair, sighash));

    BOOST_CHECK(!Consensus::CheckMultisig44Spend(*program, {}, sighash));
    std::vector<std::vector<unsigned char>> thirteen;
    for (int i{0}; i < 13; ++i) {
        std::vector<unsigned char> skip(32, static_cast<unsigned char>(i + 1));
        thirteen.push_back(skip);
    }
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(*program, thirteen, sighash));
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
    AppendSkipped(two_sig, holders[2].hash);
    BOOST_CHECK(Consensus::CheckMultisig87Spend(*program, two_sig, sighash));
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(*program, two_sig, sighash));

    const Holder44 outsider{MakeHolder44(8)};
    std::vector<std::vector<unsigned char>> mixed;
    AppendSigned44(mixed, outsider, sighash);
    AppendSigned87(mixed, holders[1], sighash);
    AppendSkipped(mixed, holders[2].hash);
    BOOST_CHECK(!Consensus::CheckMultisig87Spend(*program, mixed, sighash));
    BOOST_CHECK(!Consensus::CheckMultisig44Spend(*program, mixed, sighash));

    const auto program44{Consensus::MlDsa44PolicyProgram(1, std::array<uint256, 1>{outsider.hash})};
    BOOST_REQUIRE(program44);
    BOOST_CHECK(!Consensus::CheckMultisig87Spend(*program44, two_sig, sighash));
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
    AppendSkipped(partial_a, holders[1].hash);
    std::vector<std::vector<unsigned char>> partial_b;
    AppendSkipped(partial_b, holders[0].hash);
    AppendSigned87(partial_b, holders[1], sighash);

    const auto merged{Consensus::MergeMlDsa87Witnesses({partial_a, partial_b}, sighash)};
    BOOST_REQUIRE(merged);
    BOOST_CHECK(Consensus::CheckMultisig87Spend(*program, *merged, sighash));

    BOOST_CHECK(!Consensus::MergeMlDsa87Witnesses({partial_a, partial_b}, std::span<const unsigned char>{}));
    BOOST_CHECK(!Consensus::MergeMlDsa44Witnesses({partial_a, partial_b}, sighash));

    std::vector<std::vector<unsigned char>> other = partial_b;
    std::fill(other[0].begin(), other[0].end(), static_cast<unsigned char>(0x22));
    BOOST_CHECK(!Consensus::MergeMlDsa87Witnesses({partial_a, other}, sighash));
}

BOOST_AUTO_TEST_CASE(policy_matrix_44_and_87)
{
    const UniValue vec{LoadVectors()};
    const UniValue& hx{vec["hex_display_sort"]};
    const uint256 h_lo{HashFromHex(hx["h_lo"].get_str())};
    const uint256 h_hi{HashFromHex(hx["h_hi"].get_str())};
    const std::array<uint256, 2> gethex_order{h_hi, h_lo};
    BOOST_CHECK(Consensus::MlDsa44PolicyProgram(1, gethex_order) == HashFromHex(hx["program_after_uint256_sort"].get_str()));

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
            else AppendSkipped(wit, h44[i].hash);
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
        {3, 5, 3, true},
        {3, 5, 2, false},
        {11, 12, 11, true},
        {11, 12, 10, false},
        {12, 12, 12, true},
        {12, 12, 11, false},
    };
    for (const auto& row : rows) {
        const auto program{Consensus::MlDsa44PolicyProgram(static_cast<uint8_t>(row.t), hashes44(row.n))};
        BOOST_REQUIRE(program);
        BOOST_CHECK_EQUAL(Consensus::CheckMultisig44Spend(*program, wit44(row.n, row.signed_ok), sighash), row.expect);
    }

    {
        const auto program{Consensus::MlDsa44PolicyProgram(1, hashes44(2))};
        BOOST_REQUIRE(program);
        auto dup = wit44(2, 1);
        AppendSkipped(dup, h44[0].hash);
        BOOST_CHECK(!Consensus::CheckMultisig44Spend(*program, dup, sighash));
        auto extra = wit44(2, 2);
        AppendSkipped(extra, h44[2].hash);
        BOOST_CHECK(!Consensus::CheckMultisig44Spend(*program, extra, sighash));
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
            else AppendSkipped(wit, h87[i].hash);
        }
        return wit;
    };
    for (const auto& row : rows) {
        const auto program{Consensus::MlDsa87PolicyProgram(static_cast<uint8_t>(row.t), hashes87(row.n))};
        BOOST_REQUIRE(program);
        BOOST_CHECK_EQUAL(Consensus::CheckMultisig87Spend(*program, wit87(row.n, row.signed_ok), sighash), row.expect);
    }
    {
        const auto program{Consensus::MlDsa87PolicyProgram(1, hashes87(2))};
        BOOST_REQUIRE(program);
        auto dup = wit87(2, 1);
        AppendSkipped(dup, h87[0].hash);
        BOOST_CHECK(!Consensus::CheckMultisig87Spend(*program, dup, sighash));
        auto extra = wit87(2, 2);
        AppendSkipped(extra, h87[2].hash);
        BOOST_CHECK(!Consensus::CheckMultisig87Spend(*program, extra, sighash));
    }
}

BOOST_AUTO_TEST_CASE(p2wsh_and_op_true_rejected)
{
    CScript op_true;
    op_true << OP_TRUE;
    BOOST_CHECK_LE(op_true.size(), MAX_OUTPUT_SCRIPT_SIZE);
    CMutableTransaction created;
    created.vin.resize(1);
    created.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    created.vout.emplace_back(1, op_true);
    TxValidationState state;
    BOOST_CHECK(Consensus::CheckOutputSizes(CTransaction{created}, state));
    BOOST_CHECK(!ScriptCheckFails(op_true, {}));
    BOOST_CHECK(ScriptCheckFails(op_true, {{0x51}}));

    uint256 burn;
    std::fill(burn.begin(), burn.end(), static_cast<unsigned char>(0x11));
    const CScript v0_32{CScript() << OP_0 << std::vector<unsigned char>(burn.begin(), burn.end())};
    BOOST_CHECK_EQUAL(v0_32.size(), 34U);
    std::vector<std::vector<unsigned char>> p2wsh;
    p2wsh.push_back({OP_TRUE});
    BOOST_CHECK(ScriptCheckFails(v0_32, p2wsh));
    std::vector<std::vector<unsigned char>> p2wsh_dump;
    p2wsh_dump.push_back(std::vector<unsigned char>(80, 0xaa));
    p2wsh_dump.push_back({OP_TRUE});
    BOOST_CHECK(ScriptCheckFails(v0_32, p2wsh_dump));
    BOOST_CHECK(Consensus::ClassifyMlDsa44Witness(p2wsh_dump) == Consensus::MlDsa44WitnessLayout::Neither);
    BOOST_CHECK(Consensus::ClassifyMlDsa87Witness(p2wsh_dump) == Consensus::MlDsa87WitnessLayout::Neither);
}

BOOST_AUTO_TEST_SUITE_END()
