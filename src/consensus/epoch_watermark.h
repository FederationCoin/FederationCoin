// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_EPOCH_WATERMARK_H
#define BITCOIN_CONSENSUS_EPOCH_WATERMARK_H

#include <consensus/flex_weight.h>
#include <serialize.h>

#include <array>
#include <cstdint>

namespace Consensus {

struct EpochWatermark {
    std::array<uint64_t, FLEX_WINDOW_COUNT> window_weight{};
    std::array<uint32_t, FLEX_WINDOW_COUNT> window_blocks{};

    SERIALIZE_METHODS(EpochWatermark, obj)
    {
        for (int i{0}; i < FLEX_WINDOW_COUNT; ++i) {
            READWRITE(obj.window_weight[i]);
            READWRITE(obj.window_blocks[i]);
        }
    }

    void Clear()
    {
        window_weight.fill(0);
        window_blocks.fill(0);
    }

    void AddBlock(uint64_t weight, int height, int interval)
    {
        const int idx{FlexWindowIndex(height, interval)};
        window_weight[idx] += weight;
        window_blocks[idx] += 1;
    }

    int HotWindows(uint64_t cap) const
    {
        int hot{0};
        for (int i{0}; i < FLEX_WINDOW_COUNT; ++i) {
            if (WindowIsHot(window_weight[i], cap, window_blocks[i])) ++hot;
        }
        return hot;
    }

    uint64_t TotalWeight() const
    {
        uint64_t sum{0};
        for (uint64_t w : window_weight) sum += w;
        return sum;
    }

    uint64_t CapAfter(uint64_t cap, int interval) const
    {
        return DecideNextCap(cap, HotWindows(cap), TotalWeight(), interval);
    }
};

uint64_t CapForBlock(uint64_t parent_cap, const EpochWatermark& parent_mark, int height, int interval);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_EPOCH_WATERMARK_H
