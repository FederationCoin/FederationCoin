// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/epoch_watermark.h>

namespace Consensus {

uint64_t CapForBlock(uint64_t parent_cap, const EpochWatermark& parent_mark, int height, int interval)
{
    if (height <= 0 || interval <= 0) return MIN_FLEX_BLOCK_WEIGHT;
    if (height % interval == 0) return parent_mark.CapAfter(parent_cap, interval);
    return parent_cap;
}

} // namespace Consensus
