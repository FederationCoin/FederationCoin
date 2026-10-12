// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_BLOCK_LIMITS_H
#define BITCOIN_CONSENSUS_BLOCK_LIMITS_H

#include <consensus/consensus.h>
#include <consensus/flex_weight.h>

#include <cstdint>

namespace Consensus {

/** One signature-cost unit per this many weight units. Floor toward zero.
 *  Bitcoin's 80,000 cost per 4,000,000 weight is the same ratio (1 per 50). */
static constexpr uint64_t SIGOPS_WEIGHT_DIVISOR{50};

/** Policy sigops cost is one fifth of the block figure. Floor toward zero. */
static constexpr uint64_t STANDARD_TX_SIGOPS_DIVISOR{5};

/** Limits that mean "as big as a block" at one live weight cap.
 *  serialized_size and block_message_bytes are the cap itself: wire bytes
 *  are always below weight, and Dilithium spends get closest. */
struct BlockLimits {
    uint64_t weight_cap;
    uint64_t serialized_size;
    int64_t sigops_cost;
    int64_t standard_tx_sigops_cost;
    uint64_t max_outputs;
    uint64_t max_transactions;
    uint64_t compact_tx_count;
    uint64_t block_message_bytes;
};

/** Floor divisions of cap. Divisors are the named constants above, never zero.
 *  max_outputs uses the minimum serialized transaction-output weight.
 *  compact_tx_count uses MIN_SERIALIZABLE_TRANSACTION_WEIGHT. */
BlockLimits LimitsForCap(uint64_t cap);

/** Next block's serialized-size ceiling. Starts at the 2,400,000 floor.
 *  Updated when a block is connected. Not MAX_FLEX_BLOCK_WEIGHT. */
uint64_t BlockMessageReceiveLimit();
void SetBlockMessageReceiveLimit(uint64_t bytes);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_BLOCK_LIMITS_H
