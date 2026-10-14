// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/work/retarget.h>

#include <arith_uint256.h>
#include <chain.h>
#include <util/check.h>

namespace Consensus {

uint256 WorkScaleOne()
{
    return uint256::ONE;
}

uint256 ScaleAfterWindow(const uint256& prev_scale, int64_t expected, int64_t span)
{
    Assert(expected > 0);
    Assert(span > 0);
    arith_uint256 s{UintToArith256(prev_scale)};
    if (s == 0) s = 1;
    const arith_uint256 exp{static_cast<uint64_t>(expected)};
    const arith_uint256 max{~arith_uint256(0)};
    Assert(s <= max / exp);
    s *= exp;
    s /= static_cast<uint64_t>(span);
    if (s == 0) s = 1;
    return ArithToUint256(s);
}

arith_uint256 WorkFromScale(const uint256& work_scale)
{
    arith_uint256 s{UintToArith256(work_scale)};
    if (s == 0) s = 1;
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
    return ScaleAfterWindow(parent_s, expected, span);
}

} // namespace Consensus
