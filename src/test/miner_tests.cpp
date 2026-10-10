// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/settlement_fee.h>
#include <interfaces/mining.h>
#include <node/miner.h>
#include <policy/policy.h>
#include <test/util/txmempool.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using interfaces::BlockTemplate;
using interfaces::Mining;
using node::BlockAssembler;

namespace miner_tests {
struct MinerTestingSetup : public TestChain100Setup {
    void TestPackageSelection(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void TestPrioritisedMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    CTxMemPool& MakeMempool()
    {
        m_node.mempool.reset();
        bilingual_str error;
        m_node.mempool = std::make_unique<CTxMemPool>(MemPoolOptionsForTest(m_node), error);
        Assert(error.empty());
        return *m_node.mempool;
    }
    std::unique_ptr<Mining> MakeMining()
    {
        return interfaces::MakeMining(m_node);
    }
};
} // namespace miner_tests

BOOST_FIXTURE_TEST_SUITE(miner_tests, MinerTestingSetup)

void MinerTestingSetup::TestPackageSelection(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst)
{
    CTxMemPool& tx_mempool{MakeMempool()};
    auto mining{MakeMining()};
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.blockMinFeeRate = CFeeRate(10'000);

    LOCK(tx_mempool.cs);
    TestMemPoolEntryHelper entry;

    // Low-feerate parent + high-feerate child should beat a medium standalone.
    auto parent = CreateValidTransaction(
        {txFirst[0]}, {COutPoint{txFirst[0]->GetHash(), 0}}, 1, {coinbaseKey},
        {CTxOut{txFirst[0]->vout[0].nValue - 20'000, scriptPubKey}},
        std::nullopt, std::nullopt).first;
    const CAmount parent_fee{txFirst[0]->vout[0].nValue - parent.vout[0].nValue};
    AddToMempool(tx_mempool, entry.Fee(parent_fee).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(parent));

    auto medium = CreateValidTransaction(
        {txFirst[1]}, {COutPoint{txFirst[1]->GetHash(), 0}}, 1, {coinbaseKey},
        {CTxOut{txFirst[1]->vout[0].nValue - 40'000, scriptPubKey}},
        std::nullopt, std::nullopt).first;
    const CAmount medium_fee{txFirst[1]->vout[0].nValue - medium.vout[0].nValue};
    AddToMempool(tx_mempool, entry.Fee(medium_fee).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(medium));

    auto child = CreateValidTransaction(
        {MakeTransactionRef(parent)}, {COutPoint{parent.GetHash(), 0}}, 101, {coinbaseKey},
        {CTxOut{parent.vout[0].nValue - 200'000, scriptPubKey}},
        std::nullopt, std::nullopt).first;
    const CAmount child_fee{parent.vout[0].nValue - child.vout[0].nValue};
    AddToMempool(tx_mempool, entry.Fee(child_fee).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(child));

    std::unique_ptr<BlockTemplate> block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 4U);
    BOOST_CHECK(block.vtx[1]->GetHash() == parent.GetHash());
    BOOST_CHECK(block.vtx[2]->GetHash() == child.GetHash());
    BOOST_CHECK(block.vtx[3]->GetHash() == medium.GetHash());
}

void MinerTestingSetup::TestPrioritisedMining(const CScript& scriptPubKey, const std::vector<CTransactionRef>& txFirst)
{
    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);

    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    options.blockMinFeeRate = CFeeRate(10'000);

    CTxMemPool& tx_mempool{MakeMempool()};
    LOCK(tx_mempool.cs);
    TestMemPoolEntryHelper entry;

    auto prio = CreateValidTransaction(
        {txFirst[0]}, {COutPoint{txFirst[0]->GetHash(), 0}}, 1, {coinbaseKey},
        {CTxOut{txFirst[0]->vout[0].nValue - 15'000, scriptPubKey}},
        std::nullopt, std::nullopt).first;
    const CAmount prio_fee{txFirst[0]->vout[0].nValue - prio.vout[0].nValue};
    AddToMempool(tx_mempool, entry.Fee(prio_fee).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(prio));
    tx_mempool.PrioritiseTransaction(prio.GetHash(), 5 * COIN);

    auto parent = CreateValidTransaction(
        {txFirst[1]}, {COutPoint{txFirst[1]->GetHash(), 0}}, 1, {coinbaseKey},
        {CTxOut{txFirst[1]->vout[0].nValue - 15'000, scriptPubKey}},
        std::nullopt, std::nullopt).first;
    const CAmount parent_fee{txFirst[1]->vout[0].nValue - parent.vout[0].nValue};
    AddToMempool(tx_mempool, entry.Fee(parent_fee).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(parent));

    auto child = CreateValidTransaction(
        {MakeTransactionRef(parent)}, {COutPoint{parent.GetHash(), 0}}, 101, {coinbaseKey},
        {CTxOut{parent.vout[0].nValue - 15'000, scriptPubKey}},
        std::nullopt, std::nullopt).first;
    const CAmount child_fee{parent.vout[0].nValue - child.vout[0].nValue};
    AddToMempool(tx_mempool, entry.Fee(child_fee).Time(Now<NodeSeconds>()).SpendsCoinbase(false).FromTx(child));
    tx_mempool.PrioritiseTransaction(child.GetHash(), 2 * COIN);

    auto deprio = CreateValidTransaction(
        {txFirst[2]}, {COutPoint{txFirst[2]->GetHash(), 0}}, 1, {coinbaseKey},
        {CTxOut{txFirst[2]->vout[0].nValue - 15'000, scriptPubKey}},
        std::nullopt, std::nullopt).first;
    const CAmount deprio_fee{txFirst[2]->vout[0].nValue - deprio.vout[0].nValue};
    AddToMempool(tx_mempool, entry.Fee(deprio_fee).Time(Now<NodeSeconds>()).SpendsCoinbase(true).FromTx(deprio));
    tx_mempool.PrioritiseTransaction(deprio.GetHash(), -5 * COIN);

    auto block_template = mining->createNewBlock(options);
    BOOST_REQUIRE(block_template);
    CBlock block{block_template->getBlock()};
    BOOST_REQUIRE_GE(block.vtx.size(), 3U);
    bool saw_prio{false};
    bool saw_parent{false};
    bool saw_child{false};
    bool saw_deprio{false};
    for (const auto& tx : block.vtx) {
        saw_prio |= tx->GetHash() == prio.GetHash();
        saw_parent |= tx->GetHash() == parent.GetHash();
        saw_child |= tx->GetHash() == child.GetHash();
        saw_deprio |= tx->GetHash() == deprio.GetHash();
    }
    BOOST_CHECK(saw_prio);
    BOOST_CHECK(saw_parent);
    BOOST_CHECK(saw_child);
    BOOST_CHECK(!saw_deprio);
}

BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    gArgs.ForceSetArg("-blockprioritysize", "0");

    auto mining{MakeMining()};
    BOOST_REQUIRE(mining);
    BOOST_REQUIRE(mining->createNewBlock(BlockAssembler::Options{}));

    CScript scriptPubKey = MldsaScriptPubKey();
    mineBlocks(10);
    BOOST_REQUIRE_GE(m_coinbase_txns.size(), 4U);
    std::vector<CTransactionRef> txFirst(m_coinbase_txns.begin(), m_coinbase_txns.begin() + 4);

    LOCK(cs_main);
    TestPackageSelection(scriptPubKey, txFirst);
    TestPrioritisedMining(scriptPubKey, txFirst);
}

BOOST_AUTO_TEST_SUITE_END()
