// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <attributes.h>
#include <consensus/params.h>

#include <span>
#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

/**
 * Convert nBits value to target.
 *
 * @param[in] nBits     compact representation of the target
 * @param[in] pow_limit PoW limit (consensus parameter)
 *
 * @return              the proof-of-work target or nullopt if the nBits value
 *                      is invalid (due to overflow or exceeding pow_limit)
 */
std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&) ARG_NONNULL(1) ARG_NONNULL(2);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);
bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params&);
/** Header-v2 work menu: tag, tail, digest vs nBits. Header-only (no vtx). */
bool CheckProofOfWork(const CBlockHeader& header, const Consensus::Params& params);
/** Each header independently. Fail-fast across workers. Does not take cs_main. */
bool CheckProofOfWorkBatch(std::span<const CBlockHeader> headers, const Consensus::Params& params);
/** pindex_prev is the indexed parent of headers[0]. Walk expected nBits along
 *  the in-message chain (retarget / min-diff). No digest. */
bool HeadersMatchExpectedNBits(std::span<const CBlockHeader> headers, const CBlockIndex* pindex_prev, const Consensus::Params& params) ARG_NONNULL(2);
/** Increment nNonce until CheckProofOfWork(header) succeeds. */
bool GrindProofOfWork(CBlockHeader& header, const Consensus::Params& params);

/**
 * Return false if the proof-of-work requirement specified by new_nbits at a
 * given height is not possible, given the proof-of-work on the prior block as
 * specified by old_nbits.
 *
 * Recover S from each header's kind and compact. Off-window S must match.
 * On a retarget height, S may move by at most 4 (bound-safe). Mixed-kind
 * headers at the same S are allowed even when compact nBits differ.
 *
 * Always returns true on networks where min difficulty blocks are allowed,
 * such as regtest/testnet.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height,
                                   uint32_t old_nbits, uint32_t old_complete_version,
                                   uint32_t new_nbits, uint32_t new_complete_version);

#endif // BITCOIN_POW_H
