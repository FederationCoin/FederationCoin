// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_WORK_POSEIDON2_H
#define BITCOIN_CONSENSUS_WORK_POSEIDON2_H

#include <array>
#include <cstdint>
#include <span>

class CBlockHeader;
class uint256;

namespace Consensus {

/** Goldilocks modulus p = 2^64 - 2^32 + 1. Copied from qp-poseidon-core. */
static constexpr uint64_t GOLDILOCKS_P{0xFFFFFFFF00000001ULL};

static constexpr unsigned POSEIDON2_WIDTH{12};
static constexpr unsigned POSEIDON2_RATE{8};
static constexpr unsigned POSEIDON2_OUTPUT{4};
static constexpr unsigned POSEIDON2_INTERNAL_ROUNDS{22};
static constexpr unsigned POSEIDON2_EXTERNAL_ROUNDS{8};

/** Injective 4-bytes/felt + terminator, then one permute, squeeze twice.
 *  Tables copied from qp-poseidon-core (seed 0x3141592653589793). Not a gitlink. */
std::array<unsigned char, 64> Poseidon2HashSqueezeTwice(std::span<const unsigned char> input);
std::array<unsigned char, 32> Poseidon2HashBytes(std::span<const unsigned char> input);

/** Blake2b-256("gfcn-poseidon2-pre-v1" || 166-byte header with nonce overlay zeroed). */
uint256 Poseidon2Preimage(const CBlockHeader& header);
/** nNonce||nonce2||nonce3||extranonce||time_offset||mm_rhs (64 bytes). */
std::array<unsigned char, 64> Poseidon2NonceOverlay(const CBlockHeader& header);
std::array<unsigned char, 64> Poseidon2WorkHash(const CBlockHeader& header);

void Poseidon2Permute(std::array<uint64_t, POSEIDON2_WIDTH>& state);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_WORK_POSEIDON2_H
