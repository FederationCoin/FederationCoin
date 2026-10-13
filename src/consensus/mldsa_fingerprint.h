// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MLDSA_FINGERPRINT_H
#define BITCOIN_CONSENSUS_MLDSA_FINGERPRINT_H

#include <crypto/blake2b.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <optional>
#include <string_view>
#include <vector>

namespace Consensus {

/** Blake2b-256 with a 32-byte output length. False if the primitive fails. */
inline bool Blake2b256(std::span<const unsigned char> data, uint256& out)
{
    std::array<unsigned char, 32> digest{};
    if (blake2b_nokey(digest.data(), digest.size(), data.data(), data.size()) != 0) return false;
    out = uint256{Span<const unsigned char>{digest.data(), digest.size()}};
    return true;
}

/** KEY fingerprint width (same as UNIFIED_SIGHASH_SIZE). */
static constexpr size_t MLDSA_SKIP_HASH_SIZE{32};

/** Tagged key fingerprint for this kind.
 *  Preimage is 1-byte ASCII length, then the KEY tag, then the pubkey. */
template <typename Kind>
std::optional<uint256> MlDsaTaggedKeyHash(std::span<const unsigned char> pubkey)
{
    if (pubkey.size() != Kind::PUBKEY_SIZE) return std::nullopt;
    std::vector<unsigned char> preimage;
    preimage.reserve(1 + Kind::KEY_TAG.size() + Kind::PUBKEY_SIZE);
    preimage.push_back(static_cast<unsigned char>(Kind::KEY_TAG.size()));
    preimage.insert(preimage.end(), Kind::KEY_TAG.begin(), Kind::KEY_TAG.end());
    preimage.insert(preimage.end(), pubkey.begin(), pubkey.end());
    uint256 hash;
    if (!Blake2b256(preimage, hash)) return std::nullopt;
    return hash;
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_MLDSA_FINGERPRINT_H
