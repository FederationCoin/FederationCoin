// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_MLDSA_MERGE_H
#define BITCOIN_SCRIPT_MLDSA_MERGE_H

#include <consensus/mldsa44_spend.h>
#include <consensus/mldsa87_spend.h>
#include <consensus/mldsa_policy_slots.h>
#include <consensus/secp_spend.h>

#include <optional>
#include <span>
#include <vector>

namespace Consensus {

/** Combine partial policy stacks of this kind. Signed slots win over skip
 *  hashes. Every accepted stack must share the same ordered hash list.
 *  Requires a 32-byte sighash and verifies signed slots. Any invalid stack
 *  returns nullopt (fail closed). Not a ConnectBlock checker. */
template <typename Kind>
std::optional<std::vector<std::vector<unsigned char>>> MergeMlDsaWitnesses(
    const std::vector<std::vector<std::vector<unsigned char>>>& stacks,
    std::span<const unsigned char> sighash)
{
    if (sighash.size() != UNIFIED_SIGHASH_SIZE) return std::nullopt;
    std::vector<MlDsaParsedSlot<Kind>> merged;
    bool have{false};
    for (const auto& stack : stacks) {
        const MlDsaParsedSlots<Kind> parsed{VerifyPolicySlots<Kind>(stack, sighash)};
        if (!parsed.ok) return std::nullopt;
        if (!have) {
            merged = parsed.slots;
            have = true;
            continue;
        }
        if (merged.size() != parsed.slots.size()) return std::nullopt;
        for (std::size_t i{0}; i < merged.size(); ++i) {
            if (merged[i].hash != parsed.slots[i].hash) return std::nullopt;
            if (!merged[i].signed_slot && parsed.slots[i].signed_slot) {
                merged[i] = parsed.slots[i];
            }
        }
    }
    if (!have) return std::nullopt;
    std::vector<std::vector<unsigned char>> out;
    for (const MlDsaParsedSlot<Kind>& slot : merged) {
        if (slot.signed_slot) {
            out.push_back(slot.pubkey);
            out.push_back(slot.signature);
        } else {
            out.emplace_back(slot.hash.begin(), slot.hash.end());
        }
    }
    return out;
}

inline std::optional<std::vector<std::vector<unsigned char>>> MergeMlDsa44Witnesses(
    const std::vector<std::vector<std::vector<unsigned char>>>& stacks,
    std::span<const unsigned char> sighash)
{
    return MergeMlDsaWitnesses<MlDsa44Kind>(stacks, sighash);
}

inline std::optional<std::vector<std::vector<unsigned char>>> MergeMlDsa87Witnesses(
    const std::vector<std::vector<std::vector<unsigned char>>>& stacks,
    std::span<const unsigned char> sighash)
{
    return MergeMlDsaWitnesses<MlDsa87Kind>(stacks, sighash);
}

} // namespace Consensus

#endif // BITCOIN_SCRIPT_MLDSA_MERGE_H
