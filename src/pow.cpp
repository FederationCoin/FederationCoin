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

#include <atomic>
#include <limits>
#include <list>
#include <thread>
#include <vector>

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
    if (!tag) return 0;
    const Consensus::WorkKindTag kind_tag{*tag};
    const Consensus::WorkKind* kind{Consensus::LookupWorkKind(kind_tag)};
    if (!kind) return 0;
    const uint256 S{Consensus::NextWorkScale(pindexLast, params)};
    unsigned int nBits{kind->ExpectedNBits(S, params)};

    if (params.fPowAllowMinDifficultyBlocks &&
        pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2) {
        arith_uint256 s{UintToArith256(S)};
        if (s == 0) s = 1;
        arith_uint256 floor{UintToArith256(params.powFloor0)};
        floor /= s;
        if (floor == 0) floor = 1;
        const arith_uint256 limit{UintToArith256(params.powLimitKind)};
        if (floor > limit) floor = limit;
        nBits = floor.GetCompact();
    }

    return ApplyMinDifficultyFloor(nBits, params);
}

// Compact nBits is comparable across kinds only because every kind shares
// one T0 (FillWorkMenu). A later per-kind T0 would abort mixed-kind presync
// here: equal scale would look like an illegal compact jump. Do not split T0.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;
    if (params.fPowNoRetargeting) return true;
    const int64_t interval{params.DifficultyAdjustmentInterval()};
    if (interval <= 0) return false;

    bool f_negative{false};
    bool f_overflow{false};
    arith_uint256 old_target;
    old_target.SetCompact(old_nbits, &f_negative, &f_overflow);
    if (f_negative || old_target == 0 || f_overflow) return false;
    arith_uint256 new_target;
    new_target.SetCompact(new_nbits, &f_negative, &f_overflow);
    if (f_negative || new_target == 0 || f_overflow) return false;

    if (height % interval == 0) {
        // ScaleAfterWindow clamps span to [expected/4, expected*4], so S
        // (and therefore the compact target at fixed T0) moves by at most 4x.
        if (new_target > old_target * 4) return false;
        if (old_target > new_target * 4) return false;
        return true;
    }
    return old_nbits == new_nbits;
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

bool CheckProofOfWorkBatch(std::span<const CBlockHeader> headers, const Consensus::Params& params)
{
    if (headers.empty()) return true;
    if (headers.size() == 1) return CheckProofOfWork(headers[0], params);

    std::atomic<bool> failed{false};
    std::atomic<size_t> next{0};
    unsigned workers{std::thread::hardware_concurrency()};
    if (workers == 0) workers = 1;
    if (workers > headers.size()) workers = static_cast<unsigned>(headers.size());

    std::vector<std::thread> pool;
    pool.reserve(workers);
    for (unsigned t{0}; t < workers; ++t) {
        pool.emplace_back([&] {
            while (!failed.load(std::memory_order_relaxed)) {
                const size_t i{next.fetch_add(1, std::memory_order_relaxed)};
                if (i >= headers.size()) break;
                if (!CheckProofOfWork(headers[i], params)) {
                    failed.store(true, std::memory_order_relaxed);
                    break;
                }
            }
        });
    }
    for (std::thread& th : pool) th.join();
    return !failed.load(std::memory_order_relaxed);
}

bool HeadersMatchExpectedNBits(std::span<const CBlockHeader> headers, const CBlockIndex* pindex_prev, const Consensus::Params& params)
{
    if (headers.empty()) return true;

    std::list<CBlockIndex> dummy;
    const CBlockIndex* prev{pindex_prev};
    for (const CBlockHeader& header : headers) {
        if (header.nBits != GetNextWorkRequired(prev, &header, params)) return false;
        dummy.emplace_back(header);
        CBlockIndex& idx{dummy.back()};
        idx.pprev = const_cast<CBlockIndex*>(prev);
        idx.nHeight = prev->nHeight + 1;
        idx.nWorkScale = Consensus::NextWorkScale(prev, params);
        if (params.fPowAllowMinDifficultyBlocks) {
            const auto tag{Consensus::DecodeWorkKindTag(header.GetCompleteVersion())};
            if (tag) {
                const auto met{Consensus::ScaleFromNBits(header.nBits, static_cast<size_t>(*tag), params)};
                if (met) idx.nWorkScale = *met;
            }
        }
        prev = &idx;
    }
    return true;
}

bool GrindProofOfWork(CBlockHeader& header, const Consensus::Params& params)
{
    for (uint32_t tries{0}; tries < std::numeric_limits<uint32_t>::max(); ++tries) {
        if (CheckProofOfWork(header, params)) return true;
        ++header.nNonce;
    }
    return CheckProofOfWork(header, params);
}
