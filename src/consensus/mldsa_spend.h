// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MLDSA_SPEND_H
#define BITCOIN_CONSENSUS_MLDSA_SPEND_H

#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace Consensus {

static constexpr std::size_t MLDSA44_PUBLIC_KEY_SIZE{1312};
static constexpr std::size_t MLDSA44_SIGNATURE_SIZE{2420};
static constexpr std::size_t MLDSA44_SEED_SIZE{32};
static constexpr std::size_t MLDSA44_SECRET_KEY_SIZE{2560};
static constexpr std::size_t MLDSA44_MAX_KEYS{12};

struct MlDsa44Keypair {
    std::array<unsigned char, MLDSA44_PUBLIC_KEY_SIZE> pubkey{};
    std::array<unsigned char, MLDSA44_SECRET_KEY_SIZE> secret{};
};

/** False when seed, pubkey, or signature has the wrong length. A wrong length
 *  is rejected before a buffer is grown to fit it. */
bool MlDsa44Keygen(std::span<const unsigned char> seed, MlDsa44Keypair& out);
bool MlDsa44Sign(const MlDsa44Keypair& key, std::span<const unsigned char> message, std::span<unsigned char> signature);
bool MlDsa44Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message);

uint256 MlDsa44KeyHash(std::span<const unsigned char> pubkey);
uint256 MlDsa44SingleKeyProgram(std::span<const unsigned char> pubkey);
std::optional<uint256> MlDsa44PolicyProgram(uint8_t threshold, std::span<const uint256> key_hashes);

bool CheckSingleKeySpend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash);
bool CheckMultisigSpend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash);
/** Merge slot witnesses. A signed slot wins over a skip hash. Hash lists must match. */
std::optional<std::vector<std::vector<unsigned char>>> MergeMlDsa44Witnesses(
    const std::vector<std::vector<std::vector<unsigned char>>>& stacks,
    std::span<const unsigned char> sighash);

enum class MlDsaSpendKind { Absent, Single, Multi };
MlDsaSpendKind MlDsaSpendKindOf(const std::vector<std::vector<unsigned char>>& witness);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_MLDSA_SPEND_H
