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

/** Skip slots are untyped 32-byte hashes (same width as UNIFIED_SIGHASH_SIZE). */
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

/** Tagged policy fingerprint for this kind.
 *  n must be 1..MAX_KEYS. t must be 1..n. Hashes are sorted by uint256 <
 *  (memcmp of the stored 32 bytes, not GetHex). Duplicates fail.
 *  Preimage is 1-byte ASCII length, POLICY tag, t, n, then sorted hashes. */
template <typename Kind>
std::optional<uint256> MlDsaTaggedPolicyProgram(uint8_t threshold, std::span<const uint256> key_hashes)
{
    const std::size_t count{key_hashes.size()};
    if (count < 1 || count > Kind::MAX_KEYS) return std::nullopt;
    if (threshold < 1 || threshold > count) return std::nullopt;
    std::vector<uint256> ordered(key_hashes.begin(), key_hashes.end());
    std::sort(ordered.begin(), ordered.end());
    for (std::size_t i{1}; i < ordered.size(); ++i) {
        if (!(ordered[i - 1] < ordered[i])) return std::nullopt;
    }
    std::vector<unsigned char> preimage;
    preimage.reserve(1 + Kind::POLICY_TAG.size() + 2 + count * 32);
    preimage.push_back(static_cast<unsigned char>(Kind::POLICY_TAG.size()));
    preimage.insert(preimage.end(), Kind::POLICY_TAG.begin(), Kind::POLICY_TAG.end());
    preimage.push_back(threshold);
    preimage.push_back(static_cast<unsigned char>(count));
    for (const uint256& hash : ordered) {
        preimage.insert(preimage.end(), hash.begin(), hash.end());
    }
    uint256 program;
    if (!Blake2b256(preimage, program)) return std::nullopt;
    return program;
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_MLDSA_FINGERPRINT_H
