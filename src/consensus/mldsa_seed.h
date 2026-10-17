// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MLDSA_SEED_H
#define BITCOIN_CONSENSUS_MLDSA_SEED_H

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>

namespace Consensus {

/** Domain tag for Dilithium seed derivation. Copied in doc/federation-spend.md
 *  and drongo. Do not change after MAIN. */
inline constexpr char MLDSA_SEED_TAG[]{"FederationCoin/ml-dsa-seed/v1"};

/** Closed kind ids mixed into the KDF. One leaf must not serve every kind. */
enum class MlDsaSeedKind : uint8_t {
    Dilithium44 = 1,
    Dilithium87 = 2,
    Policy44 = 3,
    Policy87 = 4,
};

static constexpr std::size_t MLDSA_DERIVED_SEED_SIZE{32};

/** Blake2b-256(tag || hd_seed || kind_id || le32(index)). False when
 *  hd_seed is empty. Output is 32 bytes. A secp child private key is not
 *  an input. */
bool DeriveMlDsaSeed(std::span<const unsigned char> hd_seed, MlDsaSeedKind kind, uint32_t index,
                     std::array<unsigned char, MLDSA_DERIVED_SEED_SIZE>& out);

/** Mix change into the KDF index. Bits 0–30 are the wallet (or policy)
 *  index. Bit 31 is set for the change chain. Receive and change at the
 *  same index must not share a seed. pos must be < 2^31. */
inline uint32_t MlDsaKdfIndex(uint32_t pos, bool change)
{
    assert(pos < 0x80000000u);
    return change ? (pos | 0x80000000u) : pos;
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_MLDSA_SEED_H
