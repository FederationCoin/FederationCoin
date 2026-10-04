// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/flex_weight.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#include <limits>

namespace Consensus {
namespace {

#if defined(_MSC_VER)
bool MulGe(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    uint64_t ab_hi{0};
    uint64_t cd_hi{0};
    const uint64_t ab_lo{_umul128(a, b, &ab_hi)};
    const uint64_t cd_lo{_umul128(c, d, &cd_hi)};
    return ab_hi > cd_hi || (ab_hi == cd_hi && ab_lo >= cd_lo);
}
#else
bool MulGe(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    return static_cast<unsigned __int128>(a) * b >= static_cast<unsigned __int128>(c) * d;
}
#endif

} // namespace

uint64_t GrowCap(uint64_t cap)
{
    if (cap > std::numeric_limits<uint64_t>::max() / 3) return cap;
    const uint64_t grown{(cap * 3) / 2};
    if (grown > MAX_FLEX_BLOCK_WEIGHT) return cap;
    return grown;
}

uint64_t ShrinkCap(uint64_t cap)
{
    const uint64_t halved{cap / 2};
    return halved < MIN_FLEX_BLOCK_WEIGHT ? MIN_FLEX_BLOCK_WEIGHT : halved;
}

bool ShouldGrow(int hot_windows)
{
    return hot_windows >= 13;
}

bool ShouldShrink(uint64_t epoch_weight, uint64_t cap, int interval)
{
    if (interval <= 0) return false;
    if (cap <= MIN_FLEX_BLOCK_WEIGHT) return false;
    // epoch_weight / (cap * interval) < 1/5  =>  epoch_weight * 5 < cap * interval
    return !MulGe(epoch_weight, 5, cap, static_cast<uint64_t>(interval));
}

bool WindowIsHot(uint64_t window_weight, uint64_t cap, uint64_t window_blocks)
{
    if (window_blocks == 0) return false;
    // window_weight / (cap * blocks) >= 4/5  =>  weight * 5 >= cap * blocks * 4
    if (cap > std::numeric_limits<uint64_t>::max() / 4) {
        return MulGe(window_weight, 5, cap, window_blocks * 4);
    }
    return MulGe(window_weight, 5, cap * 4, window_blocks);
}

uint64_t DecideNextCap(uint64_t cap, int hot_windows, uint64_t epoch_weight, int interval)
{
    if (ShouldGrow(hot_windows)) return GrowCap(cap);
    if (ShouldShrink(epoch_weight, cap, interval)) return ShrinkCap(cap);
    return cap;
}

} // namespace Consensus
