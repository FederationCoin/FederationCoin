// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MLDSA_POLICY_SLOTS_H
#define BITCOIN_CONSENSUS_MLDSA_POLICY_SLOTS_H

#include <consensus/mldsa_fingerprint.h>

#include <span.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace Consensus {

/** Next policy-stack item: a 32-byte skip hash, this kind's pubkey, or neither. */
enum class MlDsaSlotItem { Skip, Pubkey, Invalid };

/** One policy slot after a layout parse. Skip slots have only hash. */
template <typename Kind>
struct MlDsaParsedSlot {
    uint256 hash;
    bool signed_slot{false};
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> signature;
};

/** Layout (or layout+verify) result. ok is false until the whole stack is
 *  consumed with slot count in 1..MAX_KEYS. */
template <typename Kind>
struct MlDsaParsedSlots {
    std::vector<MlDsaParsedSlot<Kind>> slots;
    int signed_ok{0};
    bool ok{false};
};

/** Classify the next stack item by size.
 *  Skip is 32 bytes. Pubkey is Kind::PUBKEY_SIZE (1312 for 44, 2592 for 87).
 *  Any other length is invalid. This does not look at bytes as a hash. */
template <typename Kind>
MlDsaSlotItem ClassifyNext(std::span<const unsigned char> item)
{
    // Skip is untyped 32 bytes; a 44 hash in an 87 walk is still a skip.
    if (item.size() == MLDSA_SKIP_HASH_SIZE) return MlDsaSlotItem::Skip;
    if (item.size() == Kind::PUBKEY_SIZE) return MlDsaSlotItem::Pubkey;
    return MlDsaSlotItem::Invalid;
}

/** Record a skip slot: the 32 bytes are that key's tagged hash. Advance 1. */
template <typename Kind>
void TakeSkip(MlDsaParsedSlots<Kind>& parsed, std::span<const unsigned char> item)
{
    MlDsaParsedSlot<Kind> slot;
    slot.hash = uint256{Span<const unsigned char>{item.data(), item.size()}};
    parsed.slots.push_back(std::move(slot));
}

/** Record a signed slot: this item is the pubkey, the next must be this
 *  kind's signature (2420 for 44, 4627 for 87). Hash is the tagged key
 *  fingerprint. Does not verify. Advance 2. False if the pair is truncated
 *  or the signature length is wrong. */
template <typename Kind>
bool TakeSigned(MlDsaParsedSlots<Kind>& parsed, const std::vector<std::vector<unsigned char>>& witness, std::size_t i)
{
    if (i + 1 >= witness.size()) return false;
    const std::vector<unsigned char>& signature{witness[i + 1]};
    if (signature.size() != Kind::SIGNATURE_SIZE) return false;
    const std::vector<unsigned char>& pubkey{witness[i]};
    const std::optional<uint256> hash{MlDsaTaggedKeyHash<Kind>(pubkey)};
    if (!hash) return false;
    MlDsaParsedSlot<Kind> slot;
    slot.hash = *hash;
    slot.signed_slot = true;
    slot.pubkey = pubkey;
    slot.signature = signature;
    parsed.slots.push_back(std::move(slot));
    ++parsed.signed_ok;
    return true;
}

/** Layout-only policy parse. Consumes the whole stack as skip or signed
 *  slots of this kind. Does not verify signatures. */
template <typename Kind>
MlDsaParsedSlots<Kind> ParsePolicySlots(const std::vector<std::vector<unsigned char>>& witness)
{
    MlDsaParsedSlots<Kind> parsed;
    std::size_t i{0};
    while (i < witness.size()) {
        switch (ClassifyNext<Kind>(witness[i])) {
        case MlDsaSlotItem::Skip:
            TakeSkip<Kind>(parsed, witness[i]);
            ++i;
            break;
        case MlDsaSlotItem::Pubkey:
            if (!TakeSigned<Kind>(parsed, witness, i)) return parsed;
            i += 2;
            break;
        case MlDsaSlotItem::Invalid:
            return parsed;
        }
    }
    parsed.ok = i == witness.size() && parsed.slots.size() >= 1 && parsed.slots.size() <= Kind::MAX_KEYS;
    return parsed;
}

/** Layout parse, then ML-DSA verify of every signed slot against sighash. */
template <typename Kind>
MlDsaParsedSlots<Kind> VerifyPolicySlots(const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    MlDsaParsedSlots<Kind> parsed{ParsePolicySlots<Kind>(witness)};
    if (!parsed.ok) return parsed;
    for (const MlDsaParsedSlot<Kind>& slot : parsed.slots) {
        if (!slot.signed_slot) continue;
        if (!Kind::Verify(slot.pubkey, slot.signature, sighash)) {
            parsed.ok = false;
            return parsed;
        }
    }
    return parsed;
}

/** True when the two-item stack is this kind's single-key shape, the
 *  pubkey fingerprints to program, and the signature verifies. */
template <typename Kind>
bool CheckSingleKeySpendOf(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    if (witness.size() != 2) return false;
    if (witness[0].size() != Kind::PUBKEY_SIZE) return false;
    if (witness[1].size() != Kind::SIGNATURE_SIZE) return false;
    const std::optional<uint256> hash{MlDsaTaggedKeyHash<Kind>(witness[0])};
    if (!hash || *hash != program) return false;
    return Kind::Verify(witness[0], witness[1], sighash);
}

/** True when this witness spends program as a policy of this kind:
 *  layout+verify, hashes strictly increasing, recovered t in 1..n matches
 *  the program, and signed_ok >= t. */
template <typename Kind>
bool CheckMultisigSpendOf(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    const MlDsaParsedSlots<Kind> parsed{ParsePolicySlots<Kind>(witness)};
    if (!parsed.ok) return false;
    for (std::size_t h{1}; h < parsed.slots.size(); ++h) {
        if (!(parsed.slots[h - 1].hash < parsed.slots[h].hash)) return false;
    }
    std::vector<uint256> hashes;
    hashes.reserve(parsed.slots.size());
    for (const MlDsaParsedSlot<Kind>& slot : parsed.slots) hashes.push_back(slot.hash);
    const uint8_t count{static_cast<uint8_t>(hashes.size())};
    std::optional<uint8_t> threshold;
    for (uint8_t t{1}; t <= count; ++t) {
        const std::optional<uint256> expected{MlDsaTaggedPolicyProgram<Kind>(t, hashes)};
        if (expected && *expected == program) {
            threshold = t;
            break;
        }
    }
    if (!threshold || parsed.signed_ok < *threshold) return false;
    const MlDsaParsedSlots<Kind> verified{VerifyPolicySlots<Kind>(witness, sighash)};
    return verified.ok;
}

/** Witness layout only. Single is exact two items of pubkey+sig sizes.
 *  Policy is a successful layout parse. Neither is anything else.
 *  A Policy layout can still fail CheckMultisigSpendOf. */
enum class MlDsaWitnessLayout { Single, Policy, Neither };

template <typename Kind>
MlDsaWitnessLayout ClassifyMlDsaWitness(const std::vector<std::vector<unsigned char>>& witness)
{
    if (witness.size() == 2 && witness[0].size() == Kind::PUBKEY_SIZE && witness[1].size() == Kind::SIGNATURE_SIZE) {
        return MlDsaWitnessLayout::Single;
    }
    const MlDsaParsedSlots<Kind> parsed{ParsePolicySlots<Kind>(witness)};
    if (parsed.ok) return MlDsaWitnessLayout::Policy;
    return MlDsaWitnessLayout::Neither;
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_MLDSA_POLICY_SLOTS_H
