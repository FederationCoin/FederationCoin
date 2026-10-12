// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MLDSA44_SPEND_H
#define BITCOIN_CONSENSUS_MLDSA44_SPEND_H

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

static constexpr std::size_t MLDSA44_PUBLIC_KEY_SIZE{1312};
static constexpr std::size_t MLDSA44_SIGNATURE_SIZE{2420};
static constexpr std::size_t MLDSA44_SEED_SIZE{32};
static constexpr std::size_t MLDSA44_SECRET_KEY_SIZE{2560};
static constexpr std::size_t MLDSA44_MAX_KEYS{12};

struct MlDsa44Keypair {
    std::array<unsigned char, MLDSA44_PUBLIC_KEY_SIZE> pubkey{};
    std::array<unsigned char, MLDSA44_SECRET_KEY_SIZE> secret{};
};

/** ML-DSA-44 kind constants for the shared fingerprint and slot templates. */
struct MlDsa44Kind {
    static constexpr std::size_t PUBKEY_SIZE{MLDSA44_PUBLIC_KEY_SIZE};
    static constexpr std::size_t SIGNATURE_SIZE{MLDSA44_SIGNATURE_SIZE};
    static constexpr std::size_t MAX_KEYS{MLDSA44_MAX_KEYS};
    static constexpr std::string_view KEY_TAG{"FCN-MLDSA44-KEY"};
    static constexpr std::string_view POLICY_TAG{"FCN-MLDSA44-POLICY"};
    static bool Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message);
};

// Length-prefix bytes are the tag length, not a mystery hex.
static_assert(MlDsa44Kind::KEY_TAG.size() == 15);
static_assert(MlDsa44Kind::POLICY_TAG.size() == 18);

/** False when seed, pubkey, or signature has the wrong length. A wrong length
 *  is rejected before a buffer is grown to fit it. */
bool MlDsa44Keygen(std::span<const unsigned char> seed, MlDsa44Keypair& out);
bool MlDsa44Sign(const MlDsa44Keypair& key, std::span<const unsigned char> message, std::span<unsigned char> signature);
/** True when pubkey and signature are ML-DSA-44 sizes and verify under the
 *  FIPS 204 context string FederationCoin. */
bool MlDsa44Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message);

/** 32-byte tagged key fingerprint (KEY tag). Null hash on a wrong pubkey size. */
uint256 MlDsa44KeyHash(std::span<const unsigned char> pubkey);
/** Single-key program is the key fingerprint. */
uint256 MlDsa44SingleKeyProgram(std::span<const unsigned char> pubkey);
/** Policy program, or nullopt if n is not 1..12, t is not 1..n, or hashes
 *  are not unique after uint256 sort. */
std::optional<uint256> MlDsa44PolicyProgram(uint8_t threshold, std::span<const uint256> key_hashes);

/** True when this two-item witness spends program as ML-DSA-44 single-key. */
bool CheckSingleKey44Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash);
/** True when this witness spends program as an ML-DSA-44 policy: 44 sizes
 *  only, hashes strictly increasing, recovered t, signed_ok >= t. */
bool CheckMultisig44Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash);

using MlDsa44WitnessLayout = MlDsaWitnessLayout;
/** Shape only: Single, Policy, or Neither. Validity is CheckSingleKey44Spend
 *  / CheckMultisig44Spend. */
MlDsa44WitnessLayout ClassifyMlDsa44Witness(const std::vector<std::vector<unsigned char>>& witness);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_MLDSA44_SPEND_H
