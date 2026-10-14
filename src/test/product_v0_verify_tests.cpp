// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/mldsa44_spend.h>
#include <consensus/mldsa87_spend.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/modern_sig.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/transaction_identifier.h>
#include <validation.h>

#include <array>
#include <span>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(product_v0_verify_tests, BasicTestingSetup)

static constexpr unsigned int VERIFY_FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_UNIFIED_SIGHASH};

struct SignedSpend {
    CTransaction tx;
    CTxOut spent;
    mutable PrecomputedTransactionData txdata;
    SignedSpend(CMutableTransaction mtx, CTxOut spent_in)
        : tx(std::move(mtx)), spent(std::move(spent_in))
    {
        txdata.Init(tx, {spent}, /*force=*/true);
    }
};

static SignedSpend FinishSpend(CMutableTransaction mtx, CTxOut spent)
{
    return SignedSpend(std::move(mtx), std::move(spent));
}

static bool VerifySpend(const SignedSpend& spend, ScriptError* err = nullptr)
{
    TransactionSignatureChecker checker(&spend.tx, 0, spend.spent.nValue, spend.txdata, MissingDataBehavior::ASSERT_FAIL);
    return VerifyScript(spend.tx.vin[0].scriptSig, spend.spent.scriptPubKey,
                        &spend.tx.vin[0].scriptWitness, VERIFY_FLAGS, checker, err);
}

static bool ScriptCheckSpend(const SignedSpend& spend)
{
    CScriptCheck check(spend.spent, spend.tx, 0, &spend.txdata);
    return !check().has_value();
}

static CMutableTransaction BaseMtx()
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 25000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return mtx;
}

static SignedSpend SignSecpUnified()
{
    const CKey key{GenerateRandomKey()};
    const CPubKey pub{key.GetPubKey()};
    const uint160 program{Hash160(pub)};
    CTxOut spent{50000, CScript() << OP_0 << ToByteVector(program)};
    CMutableTransaction mtx{BaseMtx()};
    PrecomputedTransactionData sign_data;
    sign_data.Init(mtx, {spent}, /*force=*/true);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashUnified(sighash, CScript{}, mtx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, sign_data));
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    sig.push_back(SIGHASH_ALL | SIGHASH_UNIFIED);
    mtx.vin[0].scriptWitness.stack = {sig, {pub.begin(), pub.end()}};
    return FinishSpend(std::move(mtx), spent);
}

static SignedSpend SignSecpBip143Only()
{
    const CKey key{GenerateRandomKey()};
    const CPubKey pub{key.GetPubKey()};
    const uint160 program{Hash160(pub)};
    CTxOut spent{50000, CScript() << OP_0 << ToByteVector(program)};
    CMutableTransaction mtx{BaseMtx()};
    PrecomputedTransactionData sign_data;
    sign_data.Init(mtx, {spent}, /*force=*/true);
    CScript scriptCode;
    scriptCode << OP_DUP << OP_HASH160 << ToByteVector(program) << OP_EQUALVERIFY << OP_CHECKSIG;
    const uint256 sighash{SignatureHash(scriptCode, mtx, 0, SIGHASH_ALL, spent.nValue, SigVersion::WITNESS_V0, &sign_data)};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));
    sig.push_back(SIGHASH_ALL);
    mtx.vin[0].scriptWitness.stack = {sig, {pub.begin(), pub.end()}};
    return FinishSpend(std::move(mtx), spent);
}

static SignedSpend Sign44Unified()
{
    Consensus::MlDsa44Keypair key;
    std::array<unsigned char, Consensus::MLDSA44_SEED_SIZE> seed{};
    seed[31] = 9;
    BOOST_REQUIRE(Consensus::MlDsa44Keygen(seed, key));
    CTxOut spent{50000, BuildModernSingle(Consensus::MlDsa44SingleKeyProgram(key.pubkey), ALGO_DILITHIUM, PARAM_DILITHIUM_44)};
    CMutableTransaction mtx{BaseMtx()};
    PrecomputedTransactionData sign_data;
    sign_data.Init(mtx, {spent}, /*force=*/true);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashUnified(sighash, CScript{}, mtx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, sign_data));
    std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> signature{};
    const std::span<const unsigned char> message{sighash.begin(), 32};
    BOOST_REQUIRE(Consensus::MlDsa44Sign(key, message, signature));
    mtx.vin[0].scriptWitness.stack = {
        {key.pubkey.begin(), key.pubkey.end()},
        {signature.begin(), signature.end()},
    };
    return FinishSpend(std::move(mtx), spent);
}

static SignedSpend Sign87Unified()
{
    Consensus::MlDsa87Keypair key;
    std::array<unsigned char, Consensus::MLDSA87_SEED_SIZE> seed{};
    seed[31] = 11;
    BOOST_REQUIRE(Consensus::MlDsa87Keygen(seed, key));
    CTxOut spent{50000, BuildModernSingle(Consensus::MlDsa87SingleKeyProgram(key.pubkey), ALGO_DILITHIUM, PARAM_DILITHIUM_87)};
    CMutableTransaction mtx{BaseMtx()};
    PrecomputedTransactionData sign_data;
    sign_data.Init(mtx, {spent}, /*force=*/true);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashUnified(sighash, CScript{}, mtx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, sign_data));
    std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE> signature{};
    const std::span<const unsigned char> message{sighash.begin(), 32};
    BOOST_REQUIRE(Consensus::MlDsa87Sign(key, message, signature));
    mtx.vin[0].scriptWitness.stack = {
        {key.pubkey.begin(), key.pubkey.end()},
        {signature.begin(), signature.end()},
    };
    return FinishSpend(std::move(mtx), spent);
}

static SignedSpend Bip141P2wshOpTrue()
{
    const CScript redeem{CScript() << OP_TRUE};
    uint256 hash;
    CSHA256().Write(redeem.data(), redeem.size()).Finalize(hash.begin());
    CTxOut spent{50000, CScript() << OP_0 << ToByteVector(hash)};
    CMutableTransaction mtx{BaseMtx()};
    mtx.vin[0].scriptWitness.stack = {std::vector<unsigned char>(redeem.begin(), redeem.end())};
    return FinishSpend(std::move(mtx), spent);
}

BOOST_AUTO_TEST_CASE(verifyscript_accepts_unified_secp)
{
    const SignedSpend spend{SignSecpUnified()};
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_CHECK_MESSAGE(VerifySpend(spend, &err), ScriptErrorString(err));
    BOOST_CHECK_EQUAL(VerifySpend(spend), ScriptCheckSpend(spend));
}

BOOST_AUTO_TEST_CASE(verifyscript_accepts_unified_44)
{
    const SignedSpend spend{Sign44Unified()};
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_CHECK_MESSAGE(VerifySpend(spend, &err), ScriptErrorString(err));
    BOOST_CHECK_EQUAL(VerifySpend(spend), ScriptCheckSpend(spend));
}

BOOST_AUTO_TEST_CASE(verifyscript_accepts_unified_87)
{
    const SignedSpend spend{Sign87Unified()};
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_CHECK_MESSAGE(VerifySpend(spend, &err), ScriptErrorString(err));
    BOOST_CHECK_EQUAL(VerifySpend(spend), ScriptCheckSpend(spend));
}

BOOST_AUTO_TEST_CASE(verifyscript_rejects_bip141_p2wsh)
{
    const SignedSpend spend{Bip141P2wshOpTrue()};
    BOOST_CHECK(!VerifySpend(spend));
    BOOST_CHECK_EQUAL(VerifySpend(spend), ScriptCheckSpend(spend));
}

BOOST_AUTO_TEST_CASE(verifyscript_standard_includes_unified)
{
    const SignedSpend spend{SignSecpUnified()};
    ScriptError err{SCRIPT_ERR_OK};
    TransactionSignatureChecker checker(&spend.tx, 0, spend.spent.nValue, spend.txdata, MissingDataBehavior::ASSERT_FAIL);
    const unsigned int flags{STANDARD_SCRIPT_VERIFY_FLAGS};
    BOOST_CHECK(flags & SCRIPT_VERIFY_UNIFIED_SIGHASH);
    BOOST_CHECK(VerifyScript(spend.tx.vin[0].scriptSig, spend.spent.scriptPubKey,
                             &spend.tx.vin[0].scriptWitness, flags, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(verifyscript_without_unified_flag_fails)
{
    const SignedSpend spend{SignSecpUnified()};
    ScriptError err{SCRIPT_ERR_OK};
    TransactionSignatureChecker checker(&spend.tx, 0, spend.spent.nValue, spend.txdata, MissingDataBehavior::ASSERT_FAIL);
    const unsigned int flags{STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_UNIFIED_SIGHASH};
    BOOST_CHECK(!(flags & SCRIPT_VERIFY_UNIFIED_SIGHASH));
    BOOST_CHECK(!VerifyScript(spend.tx.vin[0].scriptSig, spend.spent.scriptPubKey,
                              &spend.tx.vin[0].scriptWitness, flags, checker, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);
}

BOOST_AUTO_TEST_CASE(verifyscript_rejects_bip143_only_secp)
{
    const SignedSpend spend{SignSecpBip143Only()};
    BOOST_CHECK(!VerifySpend(spend));
    BOOST_CHECK_EQUAL(VerifySpend(spend), ScriptCheckSpend(spend));
}

BOOST_AUTO_TEST_CASE(verifyscript_fails_closed_without_txdata)
{
    const SignedSpend spend{Sign44Unified()};
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_CHECK(!VerifyScript(spend.tx.vin[0].scriptSig, spend.spent.scriptPubKey,
                              &spend.tx.vin[0].scriptWitness, VERIFY_FLAGS, BaseSignatureChecker(), &err));
}

BOOST_AUTO_TEST_CASE(count_witness_sigops_dilithium_is_kind_cost)
{
    CScript spk;
    spk << OP_0 << std::vector<unsigned char>(WITNESS_V0_SCRIPTHASH_SIZE, 0x11);
    CScriptWitness wit;
    wit.stack.push_back(std::vector<unsigned char>(Consensus::MLDSA87_PUBLIC_KEY_SIZE, 0x02));
    wit.stack.push_back(std::vector<unsigned char>(Consensus::MLDSA87_SIGNATURE_SIZE, OP_CHECKSIG));
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(), spk, &wit, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS), 0U);
}

BOOST_AUTO_TEST_CASE(count_witness_sigops_secp_v0_is_one)
{
    CScript spk;
    spk << OP_0 << std::vector<unsigned char>(WITNESS_V0_KEYHASH_SIZE, 0x11);
    CScriptWitness wit;
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(), spk, &wit, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS), 1U);
}

BOOST_AUTO_TEST_CASE(produce_signature_completeness_is_verifyscript)
{
    FillableSigningProvider keystore;
    const CKey key{GenerateRandomKey()};
    BOOST_REQUIRE(keystore.AddKey(key));
    const CPubKey pub{key.GetPubKey()};
    const CScript spk{CScript() << OP_0 << ToByteVector(uint160{Hash160(pub)})};
    CTxOut spent{50000, spk};
    CMutableTransaction mtx{BaseMtx()};
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, {spent}, /*force=*/true);
    MutableTransactionSignatureCreator creator(mtx, 0, spent.nValue, &txdata, SIGHASH_ALL | SIGHASH_UNIFIED);
    creator.SetSighashRules(SighashRules::UNIFIED);
    SignatureData sigdata;
    BOOST_CHECK(ProduceSignature(keystore, creator, spk, sigdata));
    BOOST_CHECK(sigdata.complete);
    mtx.vin[0].scriptSig = sigdata.scriptSig;
    mtx.vin[0].scriptWitness = sigdata.scriptWitness;
    const SignedSpend spend{FinishSpend(std::move(mtx), spent)};
    ScriptError err{SCRIPT_ERR_OK};
    BOOST_CHECK_MESSAGE(VerifySpend(spend, &err), ScriptErrorString(err));
}

BOOST_AUTO_TEST_SUITE_END()
