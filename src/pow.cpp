// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/work/kind.h>
#include <consensus/work/retarget.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

#include <limits>

/** Do not ease past nMinDifficultyBits (smaller target = harder). */
static unsigned int ApplyMinDifficultyFloor(unsigned int nBits, const Consensus::Params& params)
{
    if (params.nMinDifficultyBits == 0) {
        return nBits;
    }
    arith_uint256 bn;
    bn.SetCompact(nBits);
    arith_uint256 floor_target;
    floor_target.SetCompact(params.nMinDifficultyBits);
    if (bn > floor_target) {
        return params.nMinDifficultyBits;
    }
    return nBits;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const auto tag{Consensus::DecodeWorkKindTag(pblock->GetCompleteVersion())};
    const Consensus::WorkKindTag kind_tag{tag ? *tag : Consensus::WorkKindTag::BLAKE2B};
    const Consensus::WorkKind* kind{Consensus::LookupWorkKind(kind_tag)};
    Assert(kind);
    const uint256 S{Consensus::NextWorkScale(pindexLast, params)};
    unsigned int nBits{kind->ExpectedNBits(S, params)};

    if (params.fPowAllowMinDifficultyBlocks &&
        pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2) {
        const size_t idx{static_cast<size_t>(kind_tag)};
        arith_uint256 s{UintToArith256(S)};
        if (s == 0) s = 1;
        arith_uint256 floor{UintToArith256(params.powFloor0[idx])};
        floor /= s;
        if (floor == 0) floor = 1;
        const arith_uint256 limit{UintToArith256(params.powLimitKind[idx])};
        if (floor > limit) floor = limit;
        nBits = floor.GetCompact();
    }

    return ApplyMinDifficultyFloor(nBits, params);
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    // Mixed kinds have different compact nBits at the same S. Equal-nBits is
    // not a consensus rule. ContextualCheckBlockHeader matches ExpectedNBits.
    (void)params;
    (void)height;
    (void)old_nbits;
    (void)new_nbits;
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if constexpr (G_FUZZING) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

bool CheckProofOfWork(const CBlockHeader& header, const Consensus::Params& params)
{
    if constexpr (G_FUZZING) return CheckProofOfWork(header.GetHash(), header.nBits, params);
    return Consensus::CheckWorkKindHeader(header, params);
}

bool GrindProofOfWork(CBlockHeader& header, const Consensus::Params& params)
{
    for (uint32_t tries{0}; tries < std::numeric_limits<uint32_t>::max(); ++tries) {
        if (CheckProofOfWork(header, params)) return true;
        ++header.nNonce;
    }
    return CheckProofOfWork(header, params);
}
