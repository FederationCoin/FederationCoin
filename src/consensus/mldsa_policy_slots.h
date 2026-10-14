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

/** Next policy-stack item: empty skip, this kind's pubkey‖sig, or neither. */
enum class MlDsaSlotItem { Skip, Signed, Invalid };

/** One policy slot after a layout parse. Skip slots have no hash on the wire. */
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

template <typename Kind>
MlDsaSlotItem ClassifyNext(std::span<const unsigned char> item)
{
    if (item.empty()) return MlDsaSlotItem::Skip;
    if (item.size() == Kind::PUBKEY_SIZE + Kind::SIGNATURE_SIZE) return MlDsaSlotItem::Signed;
    return MlDsaSlotItem::Invalid;
}

template <typename Kind>
void TakeSkip(MlDsaParsedSlots<Kind>& parsed)
{
    parsed.slots.emplace_back();
}

template <typename Kind>
bool TakeSigned(MlDsaParsedSlots<Kind>& parsed, std::span<const unsigned char> item)
{
    if (item.size() != Kind::PUBKEY_SIZE + Kind::SIGNATURE_SIZE) return false;
    const std::span<const unsigned char> pubkey{item.data(), Kind::PUBKEY_SIZE};
    const std::span<const unsigned char> signature{item.data() + Kind::PUBKEY_SIZE, Kind::SIGNATURE_SIZE};
    const std::optional<uint256> hash{MlDsaTaggedKeyHash<Kind>(pubkey)};
    if (!hash) return false;
    MlDsaParsedSlot<Kind> slot;
    slot.hash = *hash;
    slot.signed_slot = true;
    slot.pubkey.assign(pubkey.begin(), pubkey.end());
    slot.signature.assign(signature.begin(), signature.end());
    parsed.slots.push_back(std::move(slot));
    ++parsed.signed_ok;
    return true;
}

template <typename Kind>
MlDsaParsedSlots<Kind> ParsePolicySlots(const std::vector<std::vector<unsigned char>>& witness)
{
    MlDsaParsedSlots<Kind> parsed;
    for (const auto& item : witness) {
        switch (ClassifyNext<Kind>(item)) {
        case MlDsaSlotItem::Skip:
            TakeSkip<Kind>(parsed);
            break;
        case MlDsaSlotItem::Signed:
            if (!TakeSigned<Kind>(parsed, item)) return parsed;
            break;
        case MlDsaSlotItem::Invalid:
            return parsed;
        }
    }
    parsed.ok = parsed.slots.size() >= 1 && parsed.slots.size() <= Kind::MAX_KEYS;
    return parsed;
}

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

template <typename Kind>
bool CheckPolicySpendOf(uint8_t threshold, std::span<const uint256> hashes, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    const std::size_t n{hashes.size()};
    if (n < 1 || n > Kind::MAX_KEYS) return false;
    if (threshold < 1 || threshold > n) return false;
    if (witness.size() != n) return false;
    for (std::size_t i{1}; i < n; ++i) {
        if (!(hashes[i - 1] < hashes[i])) return false;
    }
    int signed_ok{0};
    for (std::size_t i{0}; i < n; ++i) {
        const std::vector<unsigned char>& item{witness[i]};
        if (item.empty()) continue;
        if (item.size() != Kind::PUBKEY_SIZE + Kind::SIGNATURE_SIZE) return false;
        const std::span<const unsigned char> pubkey{item.data(), Kind::PUBKEY_SIZE};
        const std::span<const unsigned char> signature{item.data() + Kind::PUBKEY_SIZE, Kind::SIGNATURE_SIZE};
        const std::optional<uint256> hash{MlDsaTaggedKeyHash<Kind>(pubkey)};
        if (!hash || *hash != hashes[i]) return false;
        if (!Kind::Verify(pubkey, signature, sighash)) return false;
        ++signed_ok;
    }
    return signed_ok == threshold;
}

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
