// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/block_limits.h>
#include <consensus/checked_arith.h>
#include <primitives/transaction.h>

#include <atomic>
#include <limits>
#include <variant>

namespace Consensus {
namespace {
std::atomic<uint64_t> g_admit_weight{MIN_FLEX_BLOCK_WEIGHT};

static_assert(SIGOPS_WEIGHT_DIVISOR != 0);
static_assert(STANDARD_TX_SIGOPS_DIVISOR != 0);
static_assert(std::numeric_limits<uint64_t>::max() / SIGOPS_WEIGHT_DIVISOR <=
              static_cast<uint64_t>(std::numeric_limits<int64_t>::max()));
} // namespace

BlockLimits LimitsForCap(uint64_t cap)
{
    BlockLimits out{};
    out.weight_cap = cap;
    // 1:1 ceiling. Bytes on the wire are base + witness, weight is 4*base + witness.
    out.serialized_size = cap;
    out.block_message_bytes = cap;
    out.sigops_cost = static_cast<int64_t>(cap / SIGOPS_WEIGHT_DIVISOR);
    out.standard_tx_sigops_cost = out.sigops_cost / static_cast<int64_t>(STANDARD_TX_SIGOPS_DIVISOR);

    const uint64_t output_weight{static_cast<uint64_t>(WITNESS_SCALE_FACTOR) * static_cast<uint64_t>(::GetSerializeSize(CTxOut()))};
    uint64_t outputs{0};
    if (output_weight != 0 && FloorDiv(cap, output_weight, outputs)) {
        out.max_outputs = outputs;
    }

    uint64_t compact_txs{0};
    if (FloorDiv(cap, MIN_SERIALIZABLE_TRANSACTION_WEIGHT, compact_txs)) {
        out.compact_tx_count = compact_txs;
    }
    uint64_t txs{0};
    if (FloorDiv(cap, MIN_TRANSACTION_WEIGHT, txs)) {
        out.max_transactions = txs;
    }
    return out;
}

uint64_t AdmitWeightForWindow(uint64_t tip_cap, const EpochWatermark& tip_mark, int tip_height, int interval, unsigned window)
{
    uint64_t cap{CapForBlock(tip_cap, tip_mark, tip_height + 1, interval)};
    if (interval <= 0 || window == 0) return cap;
    const int64_t last{static_cast<int64_t>(tip_height) + static_cast<int64_t>(window)};
    for (int64_t h{static_cast<int64_t>(tip_height) + 2}; h <= last; ++h) {
        if (h > 0 && h % interval == 0) {
            const GrowCapResult grown{GrowCap(cap)};
            if (const Grew* g = std::get_if<Grew>(&grown)) {
                cap = g->cap;
            } else if (const AtCeiling* c = std::get_if<AtCeiling>(&grown)) {
                cap = c->cap;
            }
        }
    }
    return cap;
}

uint64_t BlockMessageAdmitWeight()
{
    return g_admit_weight.load();
}

void SetBlockMessageAdmitWeight(uint64_t weight)
{
    g_admit_weight.store(weight);
}

uint64_t BlockMessageReceiveLimit()
{
    return LimitsForCap(BlockMessageAdmitWeight()).block_message_bytes;
}

void SetBlockMessageReceiveLimit(uint64_t bytes)
{
    // Tests pass LimitsForCap(cap).block_message_bytes; at 1:1 that is the weight.
    SetBlockMessageAdmitWeight(bytes);
}

} // namespace Consensus
