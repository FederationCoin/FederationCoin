// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa44_spend.h>
#include <consensus/mldsa87_spend.h>
#include <consensus/secp_spend.h>
#include <policy/witness_spend_kind.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(witness_spend_kind_tests, BasicTestingSetup)

static std::vector<unsigned char> Bytes(size_t n, unsigned char fill = 0x11)
{
    return std::vector<unsigned char>(n, fill);
}

BOOST_AUTO_TEST_CASE(match_p2wpkh)
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(Bytes(Consensus::BIP66_DER_SIGHASH_SIZE_MIN, 0x30));
    stack.back().back() = SIGHASH_ALL | SIGHASH_UNIFIED;
    stack.push_back(Bytes(CPubKey::COMPRESSED_SIZE, 0x02));
    const auto kind = MatchPolicyWitnessKind(0, WITNESS_V0_KEYHASH_SIZE, stack, /*p2sh=*/false);
    BOOST_REQUIRE(kind);
    BOOST_CHECK(*kind == PolicyWitnessKind::P2WPKH);
}

BOOST_AUTO_TEST_CASE(match_mldsa44)
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(Bytes(Consensus::MLDSA44_PUBLIC_KEY_SIZE));
    stack.push_back(Bytes(Consensus::MLDSA44_SIGNATURE_SIZE));
    const auto kind = MatchPolicyWitnessKind(0, WITNESS_V0_SCRIPTHASH_SIZE, stack, /*p2sh=*/false);
    BOOST_REQUIRE(kind);
    BOOST_CHECK(*kind == PolicyWitnessKind::MlDsa44);
}

BOOST_AUTO_TEST_CASE(match_mldsa87)
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(Bytes(Consensus::MLDSA87_PUBLIC_KEY_SIZE));
    stack.push_back(Bytes(Consensus::MLDSA87_SIGNATURE_SIZE));
    const auto kind = MatchPolicyWitnessKind(0, WITNESS_V0_SCRIPTHASH_SIZE, stack, /*p2sh=*/false);
    BOOST_REQUIRE(kind);
    BOOST_CHECK(*kind == PolicyWitnessKind::MlDsa87);
}

BOOST_AUTO_TEST_CASE(match_leftover_v0_scripthash)
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(Bytes(1, 0x51));
    stack.push_back(Bytes(2, 0x51));
    const auto kind = MatchPolicyWitnessKind(0, WITNESS_V0_SCRIPTHASH_SIZE, stack, /*p2sh=*/false);
    BOOST_REQUIRE(kind);
    BOOST_CHECK(*kind == PolicyWitnessKind::LeftoverV0ScriptHash);
}

BOOST_AUTO_TEST_CASE(match_taproot)
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(Bytes(64));
    const auto kind = MatchPolicyWitnessKind(1, WITNESS_V1_TAPROOT_SIZE, stack, /*p2sh=*/false);
    BOOST_REQUIRE(kind);
    BOOST_CHECK(*kind == PolicyWitnessKind::Taproot);
    BOOST_CHECK(!MatchPolicyWitnessKind(1, WITNESS_V1_TAPROOT_SIZE, stack, /*p2sh=*/true));
}

BOOST_AUTO_TEST_CASE(unmatched_v0_keyhash_is_not_p2wpkh)
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(Bytes(1));
    BOOST_CHECK(!MatchPolicyWitnessKind(0, WITNESS_V0_KEYHASH_SIZE, stack, /*p2sh=*/false));
}

BOOST_AUTO_TEST_CASE(leftover_rejects_oversized_stack_item)
{
    CTxIn txin;
    txin.scriptWitness.stack.push_back(Bytes(MAX_STANDARD_P2WSH_STACK_ITEM_SIZE + 1));
    txin.scriptWitness.stack.push_back(Bytes(1, OP_TRUE));
    std::string reason;
    BOOST_CHECK(!ApplyPolicyWitnessKind(PolicyWitnessKind::LeftoverV0ScriptHash, txin, false, "", reason, empty_ignore_rejects));
    BOOST_CHECK_EQUAL(reason, "stackitem-size");
}

BOOST_AUTO_TEST_CASE(p2wpkh_skips_p2wsh_caps)
{
    CTxIn txin;
    txin.scriptWitness.stack.push_back(Bytes(Consensus::BIP66_DER_SIGHASH_SIZE_MAX, 0x30));
    txin.scriptWitness.stack.back().back() = SIGHASH_ALL | SIGHASH_UNIFIED;
    txin.scriptWitness.stack.push_back(Bytes(CPubKey::COMPRESSED_SIZE, 0x03));
    std::string reason;
    BOOST_CHECK(ApplyPolicyWitnessKind(PolicyWitnessKind::P2WPKH, txin, false, "", reason, empty_ignore_rejects));
}

BOOST_AUTO_TEST_CASE(taproot_annex_nonstandard)
{
    CTxIn txin;
    txin.scriptWitness.stack.push_back(Bytes(64));
    txin.scriptWitness.stack.push_back(std::vector<unsigned char>{ANNEX_TAG, 0x00});
    std::string reason;
    BOOST_CHECK(!ApplyPolicyWitnessKind(PolicyWitnessKind::Taproot, txin, false, "", reason, empty_ignore_rejects));
    BOOST_CHECK_EQUAL(reason, "taproot-annex");
}

BOOST_AUTO_TEST_SUITE_END()
