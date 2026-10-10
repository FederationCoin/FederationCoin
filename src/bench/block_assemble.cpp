// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/consensus.h>
#include <consensus/mldsa_spend.h>
#include <node/miner.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <span>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <memory>
#include <vector>

using node::BlockAssembler;

static void AssembleBlock(benchmark::Bench& bench)
{
    const auto test_setup = MakeNoLogFileContext<const TestingSetup>();

    Consensus::MlDsa44Keypair spend_mldsa;
    std::array<unsigned char, Consensus::MLDSA44_SEED_SIZE> seed{};
    seed[31] = 2;
    assert(Consensus::MlDsa44Keygen(seed, spend_mldsa));
    const CScript scriptPubKey = CScript() << OP_0 << ToByteVector(Consensus::MlDsa44SingleKeyProgram(spend_mldsa.pubkey));
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;

    // Collect some loose transactions that spend the coinbases of our mined blocks
    constexpr size_t NUM_BLOCKS{200};
    std::array<CTransactionRef, NUM_BLOCKS - COINBASE_MATURITY + 1> txs;
    for (size_t b{0}; b < NUM_BLOCKS; ++b) {
        const COutPoint prev{MineBlock(test_setup->m_node, options)};
        if (NUM_BLOCKS - b < COINBASE_MATURITY) continue;
        CTxOut spent;
        {
            LOCK(::cs_main);
            spent = test_setup->m_node.chainman->ActiveChainstate().CoinsTip().AccessCoin(prev).out;
        }
        CMutableTransaction tx;
        tx.vin.emplace_back(prev);
        tx.vout.emplace_back(1337, scriptPubKey);
        PrecomputedTransactionData txdata;
        txdata.Init(tx, {spent}, /*force=*/true);
        uint256 sighash;
        assert(SignatureHashUnified(sighash, CScript{}, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, txdata));
        std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> signature{};
        const std::span<const unsigned char> message{sighash.begin(), 32};
        assert(Consensus::MlDsa44Sign(spend_mldsa, message, signature));
        tx.vin[0].scriptWitness.stack.emplace_back(spend_mldsa.pubkey.begin(), spend_mldsa.pubkey.end());
        tx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
        txs.at(b) = MakeTransactionRef(tx);
    }
    {
        LOCK(::cs_main);

        for (const auto& txr : txs) {
            const MempoolAcceptResult res = test_setup->m_node.chainman->ProcessTransaction(txr);
            assert(res.m_result_type == MempoolAcceptResult::ResultType::VALID);
        }
    }

    bench.run([&] {
        PrepareBlock(test_setup->m_node, options);
    });
}
static void BlockAssemblerAddPackageTxns(benchmark::Bench& bench)
{
    FastRandomContext det_rand{true};
    auto testing_setup{MakeNoLogFileContext<TestChain100Setup>()};
    testing_setup->PopulateMempool(det_rand, /*num_transactions=*/1000, /*submit=*/true);
    BlockAssembler::Options assembler_options;
    assembler_options.test_block_validity = false;
    assembler_options.coinbase_output_script = P2WSH_OP_TRUE;

    bench.run([&] {
        PrepareBlock(testing_setup->m_node, assembler_options);
    });
}

BENCHMARK(AssembleBlock, benchmark::PriorityLevel::HIGH);
BENCHMARK(BlockAssemblerAddPackageTxns, benchmark::PriorityLevel::LOW);
