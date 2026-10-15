// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_FLEX_WEIGHT_H
#define BITCOIN_CONSENSUS_FLEX_WEIGHT_H

#include <consensus/consensus.h>

#include <cstdint>
#include <variant>

namespace Consensus {

/** Leftover weight still counted as pegged, above one simplest payment.
 *  Covers a compact-size wobble on the block tx count and a few witness bytes. */
static constexpr uint64_t FULL_FIT_BUFFER_WEIGHT{64};

/** Mainnet and testnet subsidy length. cap * this interval fits in uint64_t
 *  at MAX_FLEX_BLOCK_WEIGHT. Regtest uses a shorter interval; this constant
 *  is the origin bound, not the live interval. */
static constexpr int FLEX_CEILING_INTERVAL{210000};

/** Largest cap such that cap * FLEX_CEILING_INTERVAL still fits in uint64_t.
 *  Origin bound only. GrowCap checks cap * GROW_CAP_NUM itself and does not
 *  read this as permission to skip that check. */
static constexpr uint64_t MAX_FLEX_BLOCK_WEIGHT{87841638446235ULL};

/** Floor of the live max block weight. The cap does not cut below this. */
static constexpr uint64_t MIN_FLEX_BLOCK_WEIGHT{2400000};

/** GrowCap numerator and denominator: +12 percent. Floor toward zero.
 *  GrowCap's own bound is cap <= uint64_max / GROW_CAP_NUM. */
static constexpr uint64_t GROW_CAP_NUM{28};
static constexpr uint64_t GROW_CAP_DEN{25};

/** 64x64 -> 128. hi is the top 64 bits, lo the bottom 64. Four 32x32
 *  multiplies. The mid sum is masked to 32 bits before it is shifted.
 *  Same on every CPU. This is the multiply consensus math may use. */
struct WideProduct {
    uint64_t hi;
    uint64_t lo;
};
WideProduct Mul128(uint64_t a, uint64_t b);

/** True if a * b >= c * d as unsigned 128-bit integers. No wrap. No float. */
bool MulGe(uint64_t a, uint64_t b, uint64_t c, uint64_t d);

/** True when this block's leftover weight cannot fit one more simplest
 *  payment (max signature of a kind valid at this height) plus
 *  FULL_FIT_BUFFER_WEIGHT. Demand filled the cap. weight == cap is pegged.
 *  weight > cap is not a valid block and is not pegged.
 *  Leftover-hole pegged is miner-fillable. The brake is 80% of a
 *  FLEX_CEILING_INTERVAL plus AtCeiling, not a fee-weighted oracle. */
bool Pegged(uint64_t block_weight, uint64_t cap, int height);

/** True when block_weight * 5 < cap. Strictly under 20 percent of the live
 *  max. The product is a 128-bit compare, not a uint64 multiply. */
bool Slack(uint64_t block_weight, uint64_t cap);

/** True when count * 5 >= interval * 4 (at least four fifths of the subsidy
 *  interval). Both products are 128-bit. interval <= 0 is not a stretch.
 *  For interval 210000, 167999 is false and 168000 is true. The pegged-block
 *  count and the slack-block count both use this compare. */
bool CountMeetsFourFifths(uint64_t count, int interval);

/** floor((cap * GROW_CAP_NUM) / GROW_CAP_DEN) when that product fits in
 *  uint64_t and does not pass MAX_FLEX_BLOCK_WEIGHT. Floor toward zero
 *  (cap 26 yields 29). This function's own bound is
 *  cap <= uint64_max / GROW_CAP_NUM. It does not assume the caller passed
 *  a cap under MAX_FLEX_BLOCK_WEIGHT. */
struct Grew { uint64_t cap; };
struct AtCeiling { uint64_t cap; };
struct MultiplyWouldOverflow {};
using GrowCapResult = std::variant<Grew, AtCeiling, MultiplyWouldOverflow>;
GrowCapResult GrowCap(uint64_t cap);

/** Floor toward zero of cap / 2, and not below MIN_FLEX_BLOCK_WEIGHT.
 *  Divisor is the constant 2. */
uint64_t ShrinkCap(uint64_t cap);

/** Next cap after one subsidy interval. Grow when the pegged count meets
 *  four fifths. Otherwise cut when the slack count meets four fifths.
 *  Otherwise the cap stays. One stretch takes one branch. */
uint64_t DecideNextCap(uint64_t cap, uint64_t pegged_blocks, uint64_t slack_blocks, int interval);

/** Apply GrowCap `times` times. Floor toward zero is GrowCap's. Stops
 *  on AtCeiling or MultiplyWouldOverflow so a large `times` does not
 *  spin (from MIN_FLEX, AtCeiling is about 154 steps). Does not
 *  assume the caller passed a cap under MAX_FLEX_BLOCK_WEIGHT. */
uint64_t ApplyGrowCapTimes(uint64_t cap, uint64_t times);

/** Largest live cap the chain can have reached at height: MIN_FLEX grown
 *  at every subsidy boundary from 1 through height, never cut. Stops at
 *  AtCeiling. epochs is height / interval, floor toward zero. height <= 0
 *  or interval <= 0 is MIN_FLEX. CheckBlock uses this when the parent
 *  watermark is not connected. */
uint64_t WorstCaseCapAtHeight(int height, int interval);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_FLEX_WEIGHT_H
