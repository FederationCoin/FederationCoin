// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MLDSA87_SPEND_H
#define BITCOIN_CONSENSUS_MLDSA87_SPEND_H

#include <consensus/mldsa_policy_slots.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
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

/** ML-DSA-87 kind constants for the shared fingerprint and slot templates. */
struct MlDsa87Kind {
    static constexpr std::size_t PUBKEY_SIZE{MLDSA87_PUBLIC_KEY_SIZE};
    static constexpr std::size_t SIGNATURE_SIZE{MLDSA87_SIGNATURE_SIZE};
    static constexpr std::size_t MAX_KEYS{MLDSA87_MAX_KEYS};
    static constexpr std::string_view KEY_TAG{"FCN-MLDSA87-KEY"};
    static constexpr std::string_view POLICY_TAG{"FCN-MLDSA87-POLICY"};
    static bool Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message);
};

// Length-prefix bytes are the tag length, not a mystery hex.
static_assert(MlDsa87Kind::KEY_TAG.size() == 15);
static_assert(MlDsa87Kind::POLICY_TAG.size() == 18);

/** False when seed, pubkey, or signature has the wrong length. A wrong length
 *  is rejected before a buffer is grown to fit it. */
bool MlDsa87Keygen(std::span<const unsigned char> seed, MlDsa87Keypair& out);
bool MlDsa87Sign(const MlDsa87Keypair& key, std::span<const unsigned char> message, std::span<unsigned char> signature);
/** True when pubkey and signature are ML-DSA-87 sizes and verify under the
 *  FIPS 204 context string FederationCoin. */
bool MlDsa87Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message);

/** 32-byte tagged key fingerprint (KEY tag). Null hash on a wrong pubkey size. */
uint256 MlDsa87KeyHash(std::span<const unsigned char> pubkey);
/** Single-key program is the key fingerprint. */
uint256 MlDsa87SingleKeyProgram(std::span<const unsigned char> pubkey);
/** Policy program, or nullopt if n is not 1..12, t is not 1..n, or hashes
 *  are not unique after uint256 sort. */
std::optional<uint256> MlDsa87PolicyProgram(uint8_t threshold, std::span<const uint256> key_hashes);

/** True when this two-item witness spends program as ML-DSA-87 single-key. */
bool CheckSingleKey87Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash);
/** True when this witness spends program as an ML-DSA-87 policy: 87 sizes
 *  only, hashes strictly increasing, recovered t, signed_ok >= t. */
bool CheckMultisig87Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash);
/** Merge 87 policy slot witnesses. A signed slot wins over a skip hash.
 *  Hash lists must match. Requires a 32-byte sighash and verifies. */
std::optional<std::vector<std::vector<unsigned char>>> MergeMlDsa87Witnesses(
    const std::vector<std::vector<std::vector<unsigned char>>>& stacks,
    std::span<const unsigned char> sighash);

using MlDsa87WitnessLayout = MlDsaWitnessLayout;
/** Shape only: Single, Policy, or Neither. Validity is CheckSingleKey87Spend
 *  / CheckMultisig87Spend. */
MlDsa87WitnessLayout ClassifyMlDsa87Witness(const std::vector<std::vector<unsigned char>>& witness);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_MLDSA87_SPEND_H
