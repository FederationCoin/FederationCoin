// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_BLOCK_LIMITS_H
#define BITCOIN_CONSENSUS_BLOCK_LIMITS_H

#include <consensus/consensus.h>
#include <consensus/epoch_watermark.h>
#include <consensus/flex_weight.h>

#include <cstdint>

namespace Consensus {

/** How far ahead of the tip an honest peer may still send a block message.
 *  Must stay equal to BLOCK_DOWNLOAD_WINDOW in net_processing.cpp. */
static constexpr unsigned BLOCK_MESSAGE_ADMIT_WINDOW{1024};

/** One signature-cost unit per this many weight units. Floor toward zero.
 *  Bitcoin's 80,000 cost per 4,000,000 weight is the same ratio (1 per 50).
 *  This ratio is secp-era. Dilithium spends are bounded by weight, not by
 *  this cost (their scripts carry no CHECKSIG-counted ops). */
static constexpr uint64_t SIGOPS_WEIGHT_DIVISOR{50};

/** Policy sigops cost is one fifth of the block figure. Floor toward zero. */
static constexpr uint64_t STANDARD_TX_SIGOPS_DIVISOR{5};

/** Limits that mean "as big as a block" at one live weight cap.
 *  serialized_size and block_message_bytes are the cap itself: Dilithium
 *  spends get closest (wire ≈ weight). CheckBlock compares TX_NO_WITNESS
 *  serialize (pre-malleation; witness is not trusted yet). That flag is
 *  not a no-witness block: every named spend carries witness. Live weight
 *  is ContextualCheckBlock / ConnectBlock. Do not compare stripped*4. */
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

/** Worst-case honest weight in (tip_height, tip_height + window]. Starts at
 *  CapForBlock for tip_height+1, then GrowCap at every later epoch boundary
 *  in that window. Shrink is smaller, so it is not the admit case. */
uint64_t AdmitWeightForWindow(uint64_t tip_cap, const EpochWatermark& tip_mark, int tip_height, int interval, unsigned window);

/** Live admit weight for compact / merkle ceilings. Receive bytes are
 *  LimitsForCap of this weight. Starts at MIN_FLEX_BLOCK_WEIGHT. */
uint64_t BlockMessageAdmitWeight();
void SetBlockMessageAdmitWeight(uint64_t weight);
/** Raise the receive floor to cover a header whose nFlexCap exceeds the tip window. */
void NoteHeaderFlexCap(uint64_t cap);
/** Tests restore this after a case that raised the indexed-header floor. */
void SetHeaderMaxFlex(uint64_t cap);
/** One GrowCap of max(tip admit, highest indexed nFlexCap). Slack so a
 *  sibling that grew at a subsidy boundary behind the tip is receivable. */
uint64_t BlockMessageReceiveWeight();

/** Serialized-size ceiling for block / cmpctblock / blocktxn. Derived from
 *  BlockMessageReceiveWeight(); not MAX_FLEX_BLOCK_WEIGHT. */
uint64_t BlockMessageReceiveLimit();

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_BLOCK_LIMITS_H
