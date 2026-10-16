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

/** How full this block is against the live cap. Epic 21 WindowIsHot was a
 *  1/16-slice average; epic 27 deleted slices. Fullness is leftover weight
 *  that cannot fit two simplest payments plus FULL_FIT_BUFFER_WEIGHT
 *  (Saturated). Slack is block_weight * 5 < cap. Neither is in between.
 *  Saturated is not the uint32 clamp below. */
enum class BlockFill : uint8_t {
    Saturated,
    Slack,
    Neither,
};

inline BlockFill ClassifyBlockFill(uint64_t weight, uint64_t cap, int height)
{
    if (Saturated(weight, cap, height)) return BlockFill::Saturated;
    if (Slack(weight, cap)) return BlockFill::Slack;
    return BlockFill::Neither;
}

/** True if this count is still below uint32 max. The clamp is wrap-avoidance,
 *  not Saturated(). */
inline void IncrementCountWithoutWrapping(uint32_t& count)
{
    if (count < std::numeric_limits<uint32_t>::max()) ++count;
}

inline void CountSaturated(uint32_t& saturated_blocks)
{
    IncrementCountWithoutWrapping(saturated_blocks);
}

inline void CountSlack(uint32_t& slack_blocks)
{
    IncrementCountWithoutWrapping(slack_blocks);
}

inline void CountNeither() {}

/** Running saturated-block count, slack-block count, and the decision those
 *  counts make at a subsidy-interval boundary. Saturated: leftover weight
 *  cannot fit two more simplest payments plus the 64-weight buffer. Slack:
 *  block_weight * 5 < cap. Stored on the block index. A datadir written with
 *  the old 16-window arrays will not load. Disk order is saturated then slack
 *  (same two-uint32 layout as the former pegged-then-slack fields). */
struct EpochWatermark {
    uint32_t saturated_blocks{0};
    uint32_t slack_blocks{0};

    SERIALIZE_METHODS(EpochWatermark, obj)
    {
        READWRITE(obj.saturated_blocks);
        READWRITE(obj.slack_blocks);
    }

    void Clear()
    {
        saturated_blocks = 0;
        slack_blocks = 0;
    }

    /** Count this block against cap at height. Classify once, then visit.
     *  IncrementCountWithoutWrapping is the uint32 clamp, not Saturated. */
    void AddBlock(uint64_t weight, uint64_t cap, int height)
    {
        switch (ClassifyBlockFill(weight, cap, height)) {
        case BlockFill::Saturated:
            CountSaturated(saturated_blocks);
            break;
        case BlockFill::Slack:
            CountSlack(slack_blocks);
            break;
        case BlockFill::Neither:
            CountNeither();
            break;
        }
    }

    uint64_t CapAfter(uint64_t cap, int interval) const
    {
        return DecideNextCap(cap, saturated_blocks, slack_blocks, interval);
    }
};

uint64_t CapForBlock(uint64_t parent_cap, const EpochWatermark& parent_mark, int height, int interval);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_EPOCH_WATERMARK_H
