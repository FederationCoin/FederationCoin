// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/validation.h>
#include <key.h>
#include <script/interpreter.h>
#include <script/sigcache.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

struct Dersig100Setup : public TestChain100Setup {
    Dersig100Setup()
        : TestChain100Setup{ChainType::REGTEST, {.extra_args = {"-testactivationheight=dersig@102"}}} {}
};

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, unsigned int flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks,
                       const std::vector<unsigned int>& flags_per_input = {}
) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

BOOST_AUTO_TEST_SUITE(txvalidationcache_tests)

BOOST_FIXTURE_TEST_CASE(tx_mempool_block_doublespend, Dersig100Setup)
{
    // Make sure skipping validation of transactions that were
    // validated going into the memory pool does not allow
    // double-spends in blocks to pass validation when they should not.

    CScript scriptPubKey = MldsaScriptPubKey();

    const auto ToMemPool = [this](const CMutableTransaction& tx) {
        LOCK(cs_main);

        const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx));
        return result.m_result_type == MempoolAcceptResult::ResultType::VALID;
    };

    // Create a double-spend of mature coinbase txn:
    std::vector<CMutableTransaction> spends;
    spends.resize(2);
    for (int i = 0; i < 2; i++)
    {
        spends[i] = CreateValidTransaction(
            /*input_transactions=*/{m_coinbase_txns[0]},
            /*inputs=*/{COutPoint{m_coinbase_txns[0]->GetHash(), 0}},
            /*input_height=*/1,
            /*input_signing_keys=*/{coinbaseKey},
            /*outputs=*/{CTxOut{11 * CENT * (i + 1), scriptPubKey}},
            /*feerate=*/std::nullopt,
            /*fee_output=*/std::nullopt).first;
    }

    CBlock block;

    // Test 1: block with both of those transactions should be rejected.
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }

    // Test 2: ... and should be rejected if spend1 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[0]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 1U);
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->removeRecursive(CTransaction{spends[0]}, MemPoolRemovalReason::CONFLICT));
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);

    // Test 3: ... and should be rejected if spend2 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(spends, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 1U);
    WITH_LOCK(m_node.mempool->cs, m_node.mempool->removeRecursive(CTransaction{spends[1]}, MemPoolRemovalReason::CONFLICT));
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);

    // Final sanity test: first spend in *m_node.mempool, second in block, that's OK:
    std::vector<CMutableTransaction> oneSpend;
    oneSpend.push_back(spends[0]);
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(oneSpend, scriptPubKey);
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());
    }
    // spends[1] should have been removed from the mempool when the
    // block with spends[0] is accepted:
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
}

static void CheckMldsaCache(const CTransaction& tx, bool expect_valid, CCoinsViewCache& coins, ValidationCache& cache) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    TxValidationState state;
    PrecomputedTransactionData txdata;
    const unsigned int flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_UNIFIED_SIGHASH};
    BOOST_CHECK_EQUAL(CheckInputScripts(tx, state, &coins, flags, true, true, txdata, cache, nullptr), expect_valid);
    std::vector<CScriptCheck> scriptchecks;
    BOOST_CHECK(CheckInputScripts(tx, state, &coins, flags, true, true, txdata, cache, &scriptchecks));
    if (expect_valid) {
        BOOST_CHECK(scriptchecks.empty());
    } else {
        BOOST_CHECK_EQUAL(scriptchecks.size(), tx.vin.size());
    }
}

BOOST_FIXTURE_TEST_CASE(checkinputs_test, Dersig100Setup)
{
    CScript dest = MldsaScriptPubKey();
    auto spend = CreateValidTransaction(
        /*input_transactions=*/{m_coinbase_txns[0]},
        /*inputs=*/{COutPoint{m_coinbase_txns[0]->GetHash(), 0}},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{CTxOut{11 * CENT, dest}, CTxOut{11 * CENT, dest}},
        /*feerate=*/std::nullopt,
        /*fee_output=*/std::nullopt).first;

    {
        LOCK(cs_main);
        CheckMldsaCache(CTransaction(spend), /*expect_valid=*/true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
    }

    const CBlock block = CreateAndProcessBlock({spend}, dest);
    LOCK(cs_main);
    BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());

    auto two = CreateValidTransaction(
        /*input_transactions=*/{MakeTransactionRef(spend)},
        /*inputs=*/{COutPoint{spend.GetHash(), 0}, COutPoint{spend.GetHash(), 1}},
        /*input_height=*/101,
        /*input_signing_keys=*/{coinbaseKey, coinbaseKey},
        /*outputs=*/{CTxOut{20 * CENT, dest}},
        /*feerate=*/std::nullopt,
        /*fee_output=*/std::nullopt).first;

    CheckMldsaCache(CTransaction(two), /*expect_valid=*/true, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);

    two.vin[1].scriptWitness.SetNull();
    CheckMldsaCache(CTransaction(two), /*expect_valid=*/false, m_node.chainman->ActiveChainstate().CoinsTip(), m_node.chainman->m_validation_cache);
}

BOOST_FIXTURE_TEST_CASE(checkinputs_flags_per_input_cache_safety, Dersig100Setup)
{
    CScript dest = MldsaScriptPubKey();
    auto spend = CreateValidTransaction(
        /*input_transactions=*/{m_coinbase_txns[0]},
        /*inputs=*/{COutPoint{m_coinbase_txns[0]->GetHash(), 0}},
        /*input_height=*/1,
        /*input_signing_keys=*/{coinbaseKey},
        /*outputs=*/{CTxOut{11 * CENT, dest}},
        /*feerate=*/std::nullopt,
        /*fee_output=*/std::nullopt).first;

    const unsigned int strict_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_REDUCED_DATA | SCRIPT_VERIFY_UNIFIED_SIGHASH};
    const unsigned int relaxed_flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_UNIFIED_SIGHASH};

    LOCK(cs_main);
    auto& coins_tip = m_node.chainman->ActiveChainstate().CoinsTip();
    ValidationCache validation_cache{/*script_execution_cache_bytes=*/1 << 20, /*signature_cache_bytes=*/1 << 20};

    const auto run_check{[&](const CTransaction& tx, const std::vector<unsigned int>& flags_per_input) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        TxValidationState state;
        PrecomputedTransactionData txdata;
        return CheckInputScripts(tx, state, &coins_tip, strict_flags,
                                 /*cacheSigStore=*/true, /*cacheFullScriptStore=*/true,
                                 txdata, validation_cache, /*pvChecks=*/nullptr, flags_per_input);
    }};

    const CTransaction valid{spend};
    BOOST_CHECK(run_check(valid, {}));
    BOOST_CHECK(run_check(valid, {relaxed_flags}));

    spend.vin[0].scriptWitness.SetNull();
    const CTransaction invalid{spend};
    BOOST_CHECK(!run_check(invalid, {}));
    BOOST_CHECK(!run_check(invalid, {relaxed_flags}));
}

BOOST_AUTO_TEST_SUITE_END()
