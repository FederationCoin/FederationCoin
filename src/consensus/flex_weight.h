// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_FLEX_WEIGHT_H
#define BITCOIN_CONSENSUS_FLEX_WEIGHT_H

#include <consensus/consensus.h>

#include <cstdint>

namespace Consensus {

static constexpr int FLEX_WINDOW_COUNT{16};

/** Largest cap such that cap * 210000 still fits in uint64_t. */
static constexpr uint64_t MAX_FLEX_BLOCK_WEIGHT{87841638446235ULL};
static constexpr uint64_t MIN_FLEX_BLOCK_WEIGHT{2400000};

/** True if a * b >= c * d, without wrapping the products. */
bool MulGe(uint64_t a, uint64_t b, uint64_t c, uint64_t d);
uint64_t GrowCap(uint64_t cap);
uint64_t ShrinkCap(uint64_t cap);
bool ShouldGrow(int hot_windows);
bool ShouldShrink(uint64_t epoch_weight, uint64_t cap, int interval);
bool WindowIsHot(uint64_t window_weight, uint64_t cap, uint64_t window_blocks);
uint64_t DecideNextCap(uint64_t cap, int hot_windows, uint64_t epoch_weight, int interval);

/** Mainnet/testnet watermark bound uses 210000 even on regtest. */
static constexpr int FLEX_CEILING_INTERVAL{210000};

inline int FlexWindowLength(int interval)
{
    return interval / FLEX_WINDOW_COUNT;
}

inline int FlexWindowIndex(int height, int interval)
{
    const int pos{height % interval};
    return pos / FlexWindowLength(interval);
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_FLEX_WEIGHT_H
