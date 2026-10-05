// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MLDSA87_SPEND_H
#define BITCOIN_CONSENSUS_MLDSA87_SPEND_H

#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace Consensus {

static constexpr std::size_t MLDSA87_PUBLIC_KEY_SIZE{2592};
static constexpr std::size_t MLDSA87_SIGNATURE_SIZE{4627};
static constexpr std::size_t MLDSA87_SEED_SIZE{32};
static constexpr std::size_t MLDSA87_SECRET_KEY_SIZE{4896};
static constexpr std::size_t MLDSA87_MAX_KEYS{12};

struct MlDsa87Keypair {
    std::array<unsigned char, MLDSA87_PUBLIC_KEY_SIZE> pubkey{};
    std::array<unsigned char, MLDSA87_SECRET_KEY_SIZE> secret{};
};

bool MlDsa87Keygen(std::span<const unsigned char> seed, MlDsa87Keypair& out);
bool MlDsa87Sign(const MlDsa87Keypair& key, std::span<const unsigned char> message, std::span<unsigned char> signature);
bool MlDsa87Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message);

uint256 MlDsa87KeyHash(std::span<const unsigned char> pubkey);
uint256 MlDsa87SingleKeyProgram(std::span<const unsigned char> pubkey);
std::optional<uint256> MlDsa87PolicyProgram(uint8_t threshold, std::span<const uint256> key_hashes);

bool CheckSingleKey87Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash);
bool CheckMultisig87Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash);

enum class MlDsa87SpendKind { Absent, Single, Multi };
MlDsa87SpendKind MlDsa87SpendKindOf(const std::vector<std::vector<unsigned char>>& witness);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_MLDSA87_SPEND_H
