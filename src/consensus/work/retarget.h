// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_WORK_RETARGET_H
#define BITCOIN_CONSENSUS_WORK_RETARGET_H

#include <consensus/params.h>
#include <uint256.h>

#include <cstdint>
#include <optional>

class CBlockHeader;
class CBlockIndex;
class arith_uint256;

namespace Consensus {

/** Genesis and rescued-zero scale. */
uint256 WorkScaleOne();

/**
 * S for the block that follows pindexLast. Copies parent S except on a
 * window boundary, where S := S * expected / clamp(span) (256-bit, toward
 * zero). Does not read kind clocks. Header timespan uses pblock only for
 * the testnet 2×spacing min-diff exception (caller).
 */
uint256 NextWorkScale(const CBlockIndex* pindexLast, const Params& params);

/** Bound-safe S * expected / span, floor toward zero.
 *  expected and span > 0. Input S==0 is assert. After divide, S=0 (slow
 *  window at genesis scale) becomes 1. */
uint256 ScaleAfterWindow(const uint256& prev_scale, int64_t expected, int64_t span);

/** Work added by one block at this scale. Input S==0 is assert, not clamp. */
arith_uint256 WorkFromScale(const uint256& work_scale);

/** S recovered from compact nBits: T0[k] / target, floor toward zero.
 *  Invalid compact or target above powLimitKind[k] is nullopt. */
std::optional<uint256> ScaleFromNBits(unsigned int nBits, size_t kind_index, const Params& params);

/** Anti-DoS claimed work for a header: WorkFromScale(S_met). 0 if the
 *  header is not v2 or nBits does not decode. */
arith_uint256 ClaimedWorkFromHeader(const CBlockHeader& header, const Params& params);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_WORK_RETARGET_H
