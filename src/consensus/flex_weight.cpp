// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/flex_weight.h>

#include <consensus/spend_kind_weight.h>

#include <limits>

namespace Consensus {

WideProduct Mul128(uint64_t a, uint64_t b)
{
    const uint64_t ll{uint64_t{uint32_t(a)} * uint32_t(b)};
    const uint64_t lh{uint64_t{uint32_t(a)} * (b >> 32)};
    const uint64_t hl{(a >> 32) * uint32_t(b)};
    const uint64_t hh{(a >> 32) * (b >> 32)};
    const uint64_t mid34{(ll >> 32) + uint32_t(lh) + uint32_t(hl)};
    WideProduct out;
    out.hi = hh + (lh >> 32) + (hl >> 32) + (mid34 >> 32);
    // Mask before the shift. mid34 can be up to ~3*2^32; a bare mid34<<32 is
    // not a representable uint64_t and Clang -fsanitize=integer rejects it.
    out.lo = (uint64_t{uint32_t(mid34)} << 32) | uint32_t(ll);
    return out;
}

bool MulGe(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    const WideProduct ab{Mul128(a, b)};
    const WideProduct cd{Mul128(c, d)};
    return ab.hi > cd.hi || (ab.hi == cd.hi && ab.lo >= cd.lo);
}

bool Pegged(uint64_t block_weight, uint64_t cap, int height)
{
    if (block_weight > cap) return false;
    const std::optional<uint64_t> smallest{SmallestSimplePaymentWeight(height)};
    if (!smallest) return false;
    if (*smallest > std::numeric_limits<uint64_t>::max() - FULL_FIT_BUFFER_WEIGHT) return false;
    const uint64_t hole{*smallest + FULL_FIT_BUFFER_WEIGHT};
    return (cap - block_weight) < hole;
}

bool Slack(uint64_t block_weight, uint64_t cap)
{
    // block_weight * 5 < cap, as 128-bit products.
    return !MulGe(block_weight, 5, cap, 1);
}

bool CountMeetsFourFifths(uint64_t count, int interval)
{
    if (interval <= 0) return false;
    return MulGe(count, 5, static_cast<uint64_t>(interval), 4);
}

GrowCapResult GrowCap(uint64_t cap)
{
    constexpr uint64_t times_num_max{std::numeric_limits<uint64_t>::max() / GROW_CAP_NUM};
    if (cap > times_num_max) return MultiplyWouldOverflow{};
    // Floor toward zero. The * GROW_CAP_NUM is in range because of the check above.
    const uint64_t grown{(cap * GROW_CAP_NUM) / GROW_CAP_DEN};
    if (grown > MAX_FLEX_BLOCK_WEIGHT) return AtCeiling{cap};
    return Grew{grown};
}

uint64_t ShrinkCap(uint64_t cap)
{
    // Floor toward zero. Divisor is the constant 2.
    const uint64_t halved{cap / 2};
    return halved < MIN_FLEX_BLOCK_WEIGHT ? MIN_FLEX_BLOCK_WEIGHT : halved;
}

uint64_t DecideNextCap(uint64_t cap, uint64_t pegged_blocks, uint64_t slack_blocks, int interval)
{
    if (CountMeetsFourFifths(pegged_blocks, interval)) {
        const GrowCapResult grown{GrowCap(cap)};
        if (const Grew* grew = std::get_if<Grew>(&grown)) return grew->cap;
        if (const AtCeiling* ceiling = std::get_if<AtCeiling>(&grown)) return ceiling->cap;
        // MultiplyWouldOverflow: do not grow, do not wrap.
        return cap;
    }
    if (CountMeetsFourFifths(slack_blocks, interval)) return ShrinkCap(cap);
    return cap;
}

uint64_t ApplyGrowCapTimes(uint64_t cap, uint64_t times)
{
    for (uint64_t i{0}; i < times; ++i) {
        const GrowCapResult grown{GrowCap(cap)};
        if (const AtCeiling* ceiling = std::get_if<AtCeiling>(&grown)) {
            return ceiling->cap;
        }
        if (const Grew* grew = std::get_if<Grew>(&grown)) {
            cap = grew->cap;
            continue;
        }
        return cap;
    }
    return cap;
}

uint64_t WorstCaseCapAtHeight(int height, int interval)
{
    if (height <= 0 || interval <= 0) return MIN_FLEX_BLOCK_WEIGHT;
    // Floor toward zero: height and interval are both > 0 here.
    return ApplyGrowCapTimes(MIN_FLEX_BLOCK_WEIGHT, static_cast<uint64_t>(height / interval));
}

} // namespace Consensus
