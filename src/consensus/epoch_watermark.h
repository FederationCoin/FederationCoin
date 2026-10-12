// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_EPOCH_WATERMARK_H
#define BITCOIN_CONSENSUS_EPOCH_WATERMARK_H

#include <consensus/flex_weight.h>
#include <serialize.h>

#include <cstdint>
#include <limits>

namespace Consensus {

/** Running pegged-block count, slack-block count, and the decision those
 *  counts make at a subsidy-interval boundary. Pegged: leftover weight cannot
 *  fit one more simplest payment plus the 64-weight buffer. Slack:
 *  block_weight * 5 < cap. Stored on the block index. A datadir written with
 *  the old 16-window arrays will not load. */
struct EpochWatermark {
    uint32_t pegged_blocks{0};
    uint32_t slack_blocks{0};

    SERIALIZE_METHODS(EpochWatermark, obj)
    {
        READWRITE(obj.pegged_blocks);
        READWRITE(obj.slack_blocks);
    }

    void Clear()
    {
        pegged_blocks = 0;
        slack_blocks = 0;
    }

    /** Count this block against cap at height. A block is pegged, or else
     *  slack, or neither. The count saturates at uint32 max instead of wrapping. */
    void AddBlock(uint64_t weight, uint64_t cap, int height)
    {
        if (Pegged(weight, cap, height)) {
            if (pegged_blocks < std::numeric_limits<uint32_t>::max()) ++pegged_blocks;
        } else if (Slack(weight, cap)) {
            if (slack_blocks < std::numeric_limits<uint32_t>::max()) ++slack_blocks;
        }
    }

    uint64_t CapAfter(uint64_t cap, int interval) const
    {
        return DecideNextCap(cap, pegged_blocks, slack_blocks, interval);
    }
};

uint64_t CapForBlock(uint64_t parent_cap, const EpochWatermark& parent_mark, int height, int interval);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_EPOCH_WATERMARK_H
