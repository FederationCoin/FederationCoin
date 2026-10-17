// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/work/retarget.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/work/kind.h>
#include <primitives/block.h>
#include <util/check.h>

namespace Consensus {

uint256 WorkScaleOne()
{
    return uint256::ONE;
}

std::optional<uint256> ScaleAfterWindow(const uint256& prev_scale, int64_t expected, int64_t span)
{
    if (expected <= 0 || span <= 0) return std::nullopt;
    arith_uint256 s{UintToArith256(prev_scale)};
    if (s == 0) return std::nullopt;
    const arith_uint256 exp{static_cast<uint64_t>(expected)};
    const arith_uint256 max{~arith_uint256(0)};
    if (s > max / exp) return std::nullopt;
    s *= exp;
    s /= static_cast<uint64_t>(span);
    // Floor toward zero. A slow window at genesis scale (S=1, span=4*expected)
    // yields 0; the next scale stays 1. That is the producer of a valid S, not
    // a clamp of a zero input.
    if (s == 0) s = 1;
    return ArithToUint256(s);
}

arith_uint256 WorkFromScale(const uint256& work_scale)
{
    arith_uint256 s{UintToArith256(work_scale)};
    Assert(s != 0);
    return s;
}

uint256 NextWorkScale(const CBlockIndex* pindexLast, const Params& params)
{
    if (!pindexLast) return WorkScaleOne();
    uint256 parent_s{pindexLast->nWorkScale};
    if (parent_s.IsNull()) parent_s = WorkScaleOne();
    if (params.fPowNoRetargeting) return parent_s;
    const int64_t interval{params.DifficultyAdjustmentInterval()};
    Assert(interval > 0);
    if ((pindexLast->nHeight + 1) % interval != 0) return parent_s;

    const int nHeightFirst{pindexLast->nHeight - static_cast<int>(interval - 1)};
    Assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst{pindexLast->GetAncestor(nHeightFirst)};
    if (!pindexFirst) return parent_s;

    int64_t span{pindexLast->GetBlockTime() - pindexFirst->GetBlockTime()};
    const int64_t expected{params.nPowTargetTimespan};
    Assert(expected > 0);
    if (span < expected / 4) span = expected / 4;
    if (span > expected * 4) span = expected * 4;
    if (span <= 0) span = 1;
    const auto next{ScaleAfterWindow(parent_s, expected, span)};
    if (!next) return parent_s;
    return *next;
}

std::optional<uint256> ScaleFromNBits(unsigned int nBits, size_t kind_index, const Params& params)
{
    if (kind_index >= WORK_KIND_COUNT) return std::nullopt;
    bool f_negative{false};
    bool f_overflow{false};
    arith_uint256 target;
    target.SetCompact(nBits, &f_negative, &f_overflow);
    if (f_negative || target == 0 || f_overflow) return std::nullopt;
    if (target > UintToArith256(params.powLimitKind)) return std::nullopt;
    arith_uint256 t0{UintToArith256(params.powT0)};
    if (t0 == 0) return std::nullopt;
    arith_uint256 s{t0 / target};
    if (s == 0) s = 1;
    return ArithToUint256(s);
}

arith_uint256 ClaimedWorkFromHeader(const CBlockHeader& header, const Params& params)
{
    const auto tag{DecodeWorkKindTag(header.GetCompleteVersion())};
    if (!tag) return 0;
    const auto scale{ScaleFromNBits(header.nBits, static_cast<size_t>(*tag), params)};
    if (!scale) return 0;
    return WorkFromScale(*scale);
}

} // namespace Consensus
