// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/block_limits.h>
#include <consensus/checked_arith.h>
#include <primitives/transaction.h>

#include <atomic>
#include <limits>

namespace Consensus {
namespace {
std::atomic<uint64_t> g_block_message_bytes{MIN_FLEX_BLOCK_WEIGHT};
} // namespace

uint64_t BlockMessageReceiveLimit()
{
    return g_block_message_bytes.load();
}

void SetBlockMessageReceiveLimit(uint64_t bytes)
{
    g_block_message_bytes.store(bytes);
}

BlockLimits LimitsForCap(uint64_t cap)
{
    BlockLimits out{};
    out.weight_cap = cap;
    // 1:1 ceiling. Bytes on the wire are base + witness, weight is 4*base + witness.
    out.serialized_size = cap;
    out.block_message_bytes = cap;

    uint64_t sigops{0};
    if (!FloorDiv(cap, SIGOPS_WEIGHT_DIVISOR, sigops)) sigops = 0;
    out.sigops_cost = sigops > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())
                          ? std::numeric_limits<int64_t>::max()
                          : static_cast<int64_t>(sigops);

    uint64_t standard{0};
    if (!FloorDiv(static_cast<uint64_t>(out.sigops_cost), STANDARD_TX_SIGOPS_DIVISOR, standard)) standard = 0;
    out.standard_tx_sigops_cost = static_cast<int64_t>(standard);

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

} // namespace Consensus
