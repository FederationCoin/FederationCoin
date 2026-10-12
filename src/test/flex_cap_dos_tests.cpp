// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <consensus/block_limits.h>
#include <consensus/flex_weight.h>
#include <consensus/mldsa87_spend.h>
#include <consensus/mldsa44_spend.h>
#include <consensus/settlement_fee.h>
#include <consensus/validation.h>
#include <key.h>
#include <net.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <test/util/setup_common.h>
#include <util/rbf.h>
#include <validation.h>

#include <array>
#include <deque>
#include <span>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

enum class Kind { Segwit, D44, D87, D44Policy, D87Policy };
static constexpr int KIND_COUNT{5};

struct SpendCoin {
    COutPoint outpoint;
    CTxOut out;
    Kind kind;
};

struct Holder44 {
    Consensus::MlDsa44Keypair key;
    uint256 hash;
};

struct Holder87 {
    Consensus::MlDsa87Keypair key;
    uint256 hash;
};

Holder44 Make44(unsigned char mark)
{
    std::array<unsigned char, Consensus::MLDSA44_SEED_SIZE> seed{};
    seed[31] = mark;
    Holder44 holder;
    BOOST_REQUIRE(Consensus::MlDsa44Keygen(seed, holder.key));
    holder.hash = Consensus::MlDsa44KeyHash(holder.key.pubkey);
    return holder;
}

Holder87 Make87(unsigned char mark)
{
    std::array<unsigned char, Consensus::MLDSA87_SEED_SIZE> seed{};
    seed[31] = mark;
    Holder87 holder;
    BOOST_REQUIRE(Consensus::MlDsa87Keygen(seed, holder.key));
    holder.hash = Consensus::MlDsa87KeyHash(holder.key.pubkey);
    return holder;
}

CScript ProgramScript(const uint256& program)
{
    return CScript() << OP_0 << ToByteVector(program);
}

struct SpendKeys {
    CKey secp;
    CPubKey secp_pub;
    Holder44 d44;
    Holder87 d87;
    Holder44 d44_a;
    Holder44 d44_b;
    Holder87 d87_a;
    Holder87 d87_b;
    std::array<CScript, KIND_COUNT> spk{};

    SpendKeys()
    {
        std::array<unsigned char, 32> secret{};
        secret[31] = 7;
        secp.Set(secret.begin(), secret.end(), true);
        secp_pub = secp.GetPubKey();
        d44 = Make44(11);
        d87 = Make87(12);
        d44_a = Make44(21);
        d44_b = Make44(22);
        d87_a = Make87(31);
        d87_b = Make87(32);
        if (!(d44_a.hash < d44_b.hash)) std::swap(d44_a, d44_b);
        if (!(d87_a.hash < d87_b.hash)) std::swap(d87_a, d87_b);

        spk[static_cast<int>(Kind::Segwit)] = GetScriptForDestination(WitnessV0KeyHash{secp_pub});
        spk[static_cast<int>(Kind::D44)] = ProgramScript(Consensus::MlDsa44SingleKeyProgram(d44.key.pubkey));
        spk[static_cast<int>(Kind::D87)] = ProgramScript(Consensus::MlDsa87SingleKeyProgram(d87.key.pubkey));
        const std::array<uint256, 2> d44_hashes{d44_a.hash, d44_b.hash};
        const std::array<uint256, 2> d87_hashes{d87_a.hash, d87_b.hash};
        spk[static_cast<int>(Kind::D44Policy)] = ProgramScript(*Assert(Consensus::MlDsa44PolicyProgram(2, d44_hashes)));
        spk[static_cast<int>(Kind::D87Policy)] = ProgramScript(*Assert(Consensus::MlDsa87PolicyProgram(2, d87_hashes)));
    }
};

void SignInput(const SpendKeys& keys, Kind from, CMutableTransaction& tx, const CTxOut& spent)
{
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent}, /*force=*/true);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashUnified(sighash, CScript{}, tx, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, txdata));
    const std::span<const unsigned char> message{sighash.begin(), 32};
    tx.vin[0].scriptWitness.stack.clear();
    if (from == Kind::Segwit) {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(keys.secp.Sign(sighash, sig));
        sig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_UNIFIED));
        tx.vin[0].scriptWitness.stack.push_back(std::move(sig));
        tx.vin[0].scriptWitness.stack.push_back(ToByteVector(keys.secp_pub));
        return;
    }
    if (from == Kind::D44) {
        std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> signature{};
        BOOST_REQUIRE(Consensus::MlDsa44Sign(keys.d44.key, message, signature));
        tx.vin[0].scriptWitness.stack.emplace_back(keys.d44.key.pubkey.begin(), keys.d44.key.pubkey.end());
        tx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
        return;
    }
    if (from == Kind::D87) {
        std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE> signature{};
        BOOST_REQUIRE(Consensus::MlDsa87Sign(keys.d87.key, message, signature));
        tx.vin[0].scriptWitness.stack.emplace_back(keys.d87.key.pubkey.begin(), keys.d87.key.pubkey.end());
        tx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
        return;
    }
    if (from == Kind::D44Policy) {
        for (const Holder44* holder : {&keys.d44_a, &keys.d44_b}) {
            std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> signature{};
            BOOST_REQUIRE(Consensus::MlDsa44Sign(holder->key, message, signature));
            tx.vin[0].scriptWitness.stack.emplace_back(holder->key.pubkey.begin(), holder->key.pubkey.end());
            tx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
        }
        return;
    }
    for (const Holder87* holder : {&keys.d87_a, &keys.d87_b}) {
        std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE> signature{};
        BOOST_REQUIRE(Consensus::MlDsa87Sign(holder->key, message, signature));
        tx.vin[0].scriptWitness.stack.emplace_back(holder->key.pubkey.begin(), holder->key.pubkey.end());
        tx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
    }
}

CMutableTransaction SpendOne(const SpendKeys& keys, const SpendCoin& coin, Kind to, CAmount out_value)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(coin.outpoint, CScript(), MAX_BIP125_RBF_SEQUENCE);
    tx.vout.emplace_back(out_value, keys.spk[static_cast<int>(to)]);
    SignInput(keys, coin.kind, tx, coin.out);
    const int64_t vsize{GetVirtualTransactionSize(CTransaction{tx})};
    BOOST_REQUIRE(coin.out.nValue - out_value >= MinimumFee(vsize));
    return tx;
}

struct Filled {
    std::vector<CMutableTransaction> txs;
    std::array<std::array<int, KIND_COUNT>, KIND_COUNT> cells{};
    int tail_segwit{0};
    std::vector<SpendCoin> produced;
};

Filled FillPegged(const SpendKeys& keys, std::array<std::deque<SpendCoin>, KIND_COUNT>& pool, uint64_t cap, uint64_t coinbase_weight, int height)
{
    Filled filled;
    uint64_t weight{coinbase_weight};
    int cell{0};
    const CAmount fee_gap{1000};
    while (!Consensus::Pegged(weight, cap, height)) {
        bool added{false};
        for (int attempt{0}; attempt < KIND_COUNT * KIND_COUNT; ++attempt) {
            const int slot{(cell + attempt) % (KIND_COUNT * KIND_COUNT)};
            const Kind from{static_cast<Kind>(slot / KIND_COUNT)};
            const Kind to{static_cast<Kind>(slot % KIND_COUNT)};
            auto& queue{pool[static_cast<int>(from)]};
            if (queue.empty() || queue.front().out.nValue <= fee_gap) continue;
            CMutableTransaction tx{SpendOne(keys, queue.front(), to, queue.front().out.nValue - fee_gap)};
            const uint64_t tx_weight{static_cast<uint64_t>(GetTransactionWeight(CTransaction{tx}))};
            if (weight + tx_weight > cap) break;
            weight += tx_weight;
            filled.cells[static_cast<int>(from)][static_cast<int>(to)]++;
            SpendCoin produced;
            produced.outpoint = COutPoint(tx.GetHash(), 0);
            produced.out = tx.vout[0];
            produced.kind = to;
            filled.produced.push_back(produced);
            filled.txs.push_back(std::move(tx));
            queue.pop_front();
            cell = slot + 1;
            added = true;
            break;
        }
        if (!added) break;
    }
    while (!Consensus::Pegged(weight, cap, height)) {
        auto& segwit{pool[static_cast<int>(Kind::Segwit)]};
        if (segwit.empty() || segwit.front().out.nValue <= fee_gap) break;
        CMutableTransaction tx{SpendOne(keys, segwit.front(), Kind::Segwit, segwit.front().out.nValue - fee_gap)};
        const uint64_t tx_weight{static_cast<uint64_t>(GetTransactionWeight(CTransaction{tx}))};
        if (weight + tx_weight > cap) break;
        weight += tx_weight;
        filled.tail_segwit++;
        SpendCoin produced;
        produced.outpoint = COutPoint(tx.GetHash(), 0);
        produced.out = tx.vout[0];
        produced.kind = Kind::Segwit;
        filled.produced.push_back(produced);
        filled.txs.push_back(std::move(tx));
        segwit.pop_front();
    }
    BOOST_REQUIRE(Consensus::Pegged(weight, cap, height));
    int smallest{filled.cells[0][0]};
    int largest{filled.cells[0][0]};
    for (const auto& row : filled.cells) {
        for (const int count : row) {
            smallest = std::min(smallest, count);
            largest = std::max(largest, count);
        }
    }
    BOOST_CHECK_LE(largest - smallest, 1);
    return filled;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(flex_cap_dos_tests, TestChain100Setup)

static void SetTipCap(node::NodeContext& node, uint64_t cap)
{
    LOCK(cs_main);
    CBlockIndex* tip{node.chainman->ActiveChain().Tip()};
    BOOST_REQUIRE(tip);
    tip->nFlexCap = cap;
    Consensus::SetBlockMessageReceiveLimit(Consensus::LimitsForCap(cap).block_message_bytes);
}

static void RestoreFloorLimit()
{
    Consensus::SetBlockMessageReceiveLimit(Consensus::LimitsForCap(Consensus::MIN_FLEX_BLOCK_WEIGHT).block_message_bytes);
}

static std::array<std::deque<SpendCoin>, KIND_COUNT> FundKinds(TestChain100Setup& setup, const SpendKeys& keys, uint64_t cap)
{
    const uint64_t rounds{cap / 120000 + 3};
    const uint64_t per_kind{rounds * KIND_COUNT + 4};
    const uint64_t segwit_extra{80};
    const CAmount each{10000};
    const CTransactionRef coinbase{setup.m_coinbase_txns.front()};
    const CAmount coin_value{coinbase->vout[0].nValue};
    uint64_t outputs{per_kind * KIND_COUNT + segwit_extra};
    BOOST_REQUIRE(coin_value > static_cast<CAmount>(outputs) * each);

    CMutableTransaction fund;
    fund.vin.emplace_back(COutPoint{coinbase->GetHash(), 0}, CScript(), MAX_BIP125_RBF_SEQUENCE);
    for (int kind{0}; kind < KIND_COUNT; ++kind) {
        const uint64_t count{per_kind + (kind == static_cast<int>(Kind::Segwit) ? segwit_extra : 0)};
        for (uint64_t n{0}; n < count; ++n) {
            fund.vout.emplace_back(each, keys.spk[kind]);
        }
    }
    const CTxOut spent{coinbase->vout[0]};
    PrecomputedTransactionData txdata;
    txdata.Init(fund, std::vector<CTxOut>{spent}, /*force=*/true);
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashUnified(sighash, CScript{}, fund, 0, SIGHASH_ALL | SIGHASH_UNIFIED, SigVersion::WITNESS_V0, txdata));
    std::array<unsigned char, Consensus::MLDSA44_SIGNATURE_SIZE> signature{};
    BOOST_REQUIRE(Consensus::MlDsa44Sign(setup.coinbase_mldsa, std::span<const unsigned char>{sighash.begin(), 32}, signature));
    fund.vin[0].scriptWitness.stack.emplace_back(setup.coinbase_mldsa.pubkey.begin(), setup.coinbase_mldsa.pubkey.end());
    fund.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());

    const int height_before{WITH_LOCK(cs_main, return setup.m_node.chainman->ActiveChain().Height())};
    SetMockTime(GetTime() + 1);
    setup.CreateAndProcessBlock({fund}, setup.MldsaScriptPubKey());
    BOOST_REQUIRE_EQUAL(WITH_LOCK(cs_main, return setup.m_node.chainman->ActiveChain().Height()), height_before + 1);

    std::array<std::deque<SpendCoin>, KIND_COUNT> pool;
    size_t vout{0};
    for (int kind{0}; kind < KIND_COUNT; ++kind) {
        const uint64_t count{per_kind + (kind == static_cast<int>(Kind::Segwit) ? segwit_extra : 0)};
        for (uint64_t n{0}; n < count; ++n) {
            SpendCoin coin;
            coin.outpoint = COutPoint{fund.GetHash(), static_cast<uint32_t>(vout)};
            coin.out = fund.vout[vout];
            coin.kind = static_cast<Kind>(kind);
            pool[kind].push_back(coin);
            ++vout;
        }
    }
    return pool;
}

static CBlock ConnectPegged(TestChain100Setup& setup, const std::vector<CMutableTransaction>& txs, uint64_t cap)
{
    const int height_before{WITH_LOCK(cs_main, return setup.m_node.chainman->ActiveChain().Height())};
    SetMockTime(GetTime() + 1);
    Chainstate& chainstate{setup.m_node.chainman->ActiveChainstate()};
    CBlock block{setup.CreateBlock(txs, setup.MldsaScriptPubKey(), chainstate)};
    const uint64_t weight{static_cast<uint64_t>(GetBlockWeight(block))};
    const int height{height_before + 1};
    BOOST_REQUIRE_LE(weight, cap);
    BOOST_REQUIRE(Consensus::Pegged(weight, cap, height));
    const Consensus::BlockLimits limits{Consensus::LimitsForCap(cap)};
    BOOST_CHECK(static_cast<uint64_t>(::GetSerializeSize(TX_NO_WITNESS(block))) <= limits.serialized_size);
    BOOST_CHECK(static_cast<uint64_t>(::GetSerializeSize(TX_WITH_WITNESS(block))) <= limits.block_message_bytes);
    BOOST_CHECK(static_cast<uint64_t>(::GetSerializeSize(TX_WITH_WITNESS(block))) <= CommandReceiveLimit("block"));
    uint64_t outputs{0};
    for (const auto& tx : block.vtx) outputs += tx->vout.size();
    BOOST_CHECK_LE(outputs, limits.max_outputs);
    BOOST_CHECK_LE(block.vtx.size(), limits.compact_tx_count);
    BOOST_CHECK_LE(block.vtx.size(), limits.max_transactions);

    std::shared_ptr<const CBlock> shared{std::make_shared<const CBlock>(block)};
    Assert(setup.m_node.chainman)->ProcessNewBlock(shared, true, true, nullptr);
    BOOST_REQUIRE_EQUAL(WITH_LOCK(cs_main, return setup.m_node.chainman->ActiveChain().Height()), height);
    return block;
}

BOOST_AUTO_TEST_CASE(wide_cap_connects_two_pegged_blocks)
{
    const uint64_t cap{64000000};
    const Consensus::BlockLimits limits{Consensus::LimitsForCap(cap)};
    BOOST_CHECK_EQUAL(limits.sigops_cost, 1280000);
    BOOST_CHECK(limits.serialized_size >= cap);
    SetTipCap(m_node, cap);
    const SpendKeys keys;
    const int height{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height())};
    CBlock empty{CreateBlock({}, MldsaScriptPubKey(), m_node.chainman->ActiveChainstate())};
    const uint64_t coinbase_weight{static_cast<uint64_t>(GetBlockWeight(empty))};
    auto pool{FundKinds(*this, keys, cap)};
    Filled opening{FillPegged(keys, pool, cap, coinbase_weight, height + 2)};
    ConnectPegged(*this, opening.txs, cap);
    std::array<std::deque<SpendCoin>, KIND_COUNT> next_pool;
    for (const SpendCoin& coin : opening.produced) next_pool[static_cast<int>(coin.kind)].push_back(coin);
    for (int kind{0}; kind < KIND_COUNT; ++kind) {
        for (const SpendCoin& coin : pool[kind]) next_pool[kind].push_back(coin);
    }
    const int height_after{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height())};
    Filled following{FillPegged(keys, next_pool, cap, coinbase_weight, height_after + 1)};
    CBlock block{ConnectPegged(*this, following.txs, cap)};
    BOOST_CHECK(static_cast<uint64_t>(::GetSerializeSize(TX_WITH_WITNESS(block))) <= CommandReceiveLimit("block"));
    RestoreFloorLimit();
}

BOOST_AUTO_TEST_CASE(floor_connects_pegged_and_rejects_wide_payload)
{
    const uint64_t cap{Consensus::MIN_FLEX_BLOCK_WEIGHT};
    const Consensus::BlockLimits floor{Consensus::LimitsForCap(cap)};
    const Consensus::BlockLimits wide{Consensus::LimitsForCap(64000000)};
    BOOST_CHECK_EQUAL(floor.sigops_cost, 48000);
    BOOST_CHECK_LT(floor.sigops_cost, wide.sigops_cost);
    SetTipCap(m_node, cap);
    const SpendKeys keys;
    const int height{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height())};
    CBlock empty{CreateBlock({}, MldsaScriptPubKey(), m_node.chainman->ActiveChainstate())};
    const uint64_t coinbase_weight{static_cast<uint64_t>(GetBlockWeight(empty))};
    auto pool{FundKinds(*this, keys, cap)};
    Filled opening{FillPegged(keys, pool, cap, coinbase_weight, height + 2)};
    ConnectPegged(*this, opening.txs, cap);
    std::array<std::deque<SpendCoin>, KIND_COUNT> next_pool;
    for (const SpendCoin& coin : opening.produced) next_pool[static_cast<int>(coin.kind)].push_back(coin);
    for (int kind{0}; kind < KIND_COUNT; ++kind) {
        for (const SpendCoin& coin : pool[kind]) next_pool[kind].push_back(coin);
    }
    const int height_after{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height())};
    Filled following{FillPegged(keys, next_pool, cap, coinbase_weight, height_after + 1)};
    ConnectPegged(*this, following.txs, cap);

    std::vector<CMutableTransaction> fat;
    uint64_t fat_weight{coinbase_weight};
    while (fat_weight < 64000000) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript());
        tx.vout.emplace_back(1, MldsaScriptPubKey());
        tx.vin[0].scriptWitness.stack.emplace_back(100000, static_cast<unsigned char>(1));
        fat_weight += static_cast<uint64_t>(GetTransactionWeight(CTransaction{tx}));
        fat.push_back(std::move(tx));
    }
    SetMockTime(GetTime() + 1);
    const int tip{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height())};
    CBlock heavy{CreateBlock(fat, MldsaScriptPubKey(), m_node.chainman->ActiveChainstate())};
    BOOST_REQUIRE_GT(static_cast<uint64_t>(GetBlockWeight(heavy)), cap);
    BOOST_REQUIRE_GT(static_cast<uint64_t>(::GetSerializeSize(TX_WITH_WITNESS(heavy))), CommandReceiveLimit("block"));
    std::shared_ptr<const CBlock> shared{std::make_shared<const CBlock>(heavy)};
    bool accepted{true};
    Assert(m_node.chainman)->ProcessNewBlock(shared, true, true, &accepted);
    BOOST_CHECK(!accepted);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height()), tip);
    RestoreFloorLimit();
}

BOOST_AUTO_TEST_SUITE_END()
