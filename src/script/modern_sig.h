// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_MODERN_SIG_H
#define BITCOIN_SCRIPT_MODERN_SIG_H

#include <script/script.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

class ModernSigKind;

/** Script small-int values for the closed (algorithm, param) registry.
 *  Do not push the integers 44 or 87. OP_1 / OP_2 are the only legal param
 *  encodings for Dilithium. */
static constexpr int32_t ALGO_DILITHIUM{1};
static constexpr int32_t PARAM_DILITHIUM_44{1};
static constexpr int32_t PARAM_DILITHIUM_87{2};

/** n=12 policy: OP_t + 12 * (1+32) + OP_n + algo + param + CHECK. */
static constexpr unsigned int DILITHIUM_POLICY_SCRIPT_MAX{401};
static constexpr unsigned int DILITHIUM_SINGLE_SCRIPT_SIZE{36};
static constexpr uint8_t MODERN_POLICY_MAX_KEYS{12};

/** Kind object returned by registry lookup. Sizes, KEY tag, and verify live
 *  here. The CHECK opcode does not interpret param 1 as 44. */
class ModernSigKind
{
public:
    virtual ~ModernSigKind() = default;
    virtual std::size_t PubkeySize() const = 0;
    virtual std::size_t SignatureSize() const = 0;
    virtual std::size_t CombinedWitnessSize() const = 0;
    virtual std::size_t MaxKeys() const = 0;
    /** Largest stack item this kind puts on the witness (pubkey, sig, or both). */
    virtual std::size_t MaxStackElement() const = 0;
    virtual bool KeyFingerprint(std::span<const unsigned char> pubkey, uint256& out) const = 0;
    virtual bool Verify(std::span<const unsigned char> pubkey,
                        std::span<const unsigned char> signature,
                        std::span<const unsigned char> message) const = 0;
    virtual bool VerifySingle(const uint256& fingerprint,
                              const std::vector<std::vector<unsigned char>>& witness,
                              std::span<const unsigned char> message) const = 0;
    virtual bool VerifyPolicy(uint8_t threshold,
                              std::span<const uint256> hashes,
                              const std::vector<std::vector<unsigned char>>& witness,
                              std::span<const unsigned char> message) const = 0;
};

/** Closed table keyed by (algorithm, param). Miss is nullptr. */
const ModernSigKind* LookupModernSigKind(int32_t algorithm, int32_t param);

struct ModernSingleParsed {
    uint256 fingerprint;
    int32_t algorithm{0};
    int32_t param{0};
    /** Null when the template matches but the pair is not in the registry. */
    const ModernSigKind* kind{nullptr};
};

struct ModernPolicyParsed {
    uint8_t threshold{0};
    std::vector<uint256> hashes;
    uint8_t n{0};
    int32_t algorithm{0};
    int32_t param{0};
    const ModernSigKind* kind{nullptr};
};

/** True when scriptPubKey is a single-key or policy modern-sig template
 *  (minimal 32-byte pushes, small-int t/n/algo/param). Unknown pairs still
 *  match; kind is null. Unsorted policy hashes do not match. */
bool IsModernSigTemplate(const CScript& script);
std::optional<ModernSingleParsed> MatchModernSingle(const CScript& script);
std::optional<ModernPolicyParsed> MatchModernPolicy(const CScript& script);

CScript BuildModernSingle(const uint256& fingerprint, int32_t algorithm, int32_t param);
/** Nullopt if n is not 1..12, t is not 1..n, or hashes are not unique after
 *  uint256 sort. Emits hashes in sorted order. */
std::optional<CScript> BuildModernPolicy(uint8_t threshold, std::span<const uint256> key_hashes, int32_t algorithm, int32_t param);

#endif // BITCOIN_SCRIPT_MODERN_SIG_H
