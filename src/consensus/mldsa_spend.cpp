// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa_spend.h>

#include <crypto/blake2b.h>
#include <span.h>

#include <algorithm>
#include <string>

extern "C" {
#include <crypto/mldsa44/api.h>
void mldsa44_use_seed(const uint8_t* seed, size_t len);
}

namespace Consensus {
namespace {

bool Blake2b256(std::span<const unsigned char> data, uint256& out)
{
    std::array<unsigned char, 32> digest{};
    if (blake2b_nokey(digest.data(), digest.size(), data.data(), data.size()) != 0) return false;
    out = uint256{Span<const unsigned char>{digest.data(), digest.size()}};
    return true;
}

} // namespace

bool MlDsa44Keygen(std::span<const unsigned char> seed, MlDsa44Keypair& out)
{
    if (seed.size() != MLDSA44_SEED_SIZE) return false;
    mldsa44_use_seed(seed.data(), seed.size());
    const int rc{PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(out.pubkey.data(), out.secret.data())};
    mldsa44_use_seed(nullptr, 0);
    return rc == 0;
}

bool MlDsa44Sign(const MlDsa44Keypair& key, std::span<const unsigned char> message, std::span<unsigned char> signature)
{
    if (signature.size() != MLDSA44_SIGNATURE_SIZE) return false;
    static constexpr char context[]{"FederationCoin"};
    size_t siglen{0};
    const int rc{PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(signature.data(), &siglen, message.data(), message.size(), reinterpret_cast<const uint8_t*>(context), sizeof(context) - 1, key.secret.data())};
    return rc == 0 && siglen == MLDSA44_SIGNATURE_SIZE;
}

bool MlDsa44Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message)
{
    if (pubkey.size() != MLDSA44_PUBLIC_KEY_SIZE) return false;
    if (signature.size() != MLDSA44_SIGNATURE_SIZE) return false;
    static constexpr char context[]{"FederationCoin"};
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(signature.data(), signature.size(), message.data(), message.size(), reinterpret_cast<const uint8_t*>(context), sizeof(context) - 1, pubkey.data()) == 0;
}

uint256 MlDsa44KeyHash(std::span<const unsigned char> pubkey)
{
    uint256 hash;
    if (pubkey.size() != MLDSA44_PUBLIC_KEY_SIZE) return hash;
    std::vector<unsigned char> preimage;
    preimage.reserve(1 + 15 + MLDSA44_PUBLIC_KEY_SIZE);
    preimage.push_back(0x0f);
    const std::string tag{"FCN-MLDSA44-KEY"};
    preimage.insert(preimage.end(), tag.begin(), tag.end());
    preimage.insert(preimage.end(), pubkey.begin(), pubkey.end());
    Blake2b256(preimage, hash);
    return hash;
}

uint256 MlDsa44SingleKeyProgram(std::span<const unsigned char> pubkey)
{
    return MlDsa44KeyHash(pubkey);
}

std::optional<uint256> MlDsa44PolicyProgram(uint8_t threshold, std::span<const uint256> key_hashes)
{
    const std::size_t count{key_hashes.size()};
    if (count < 1 || count > MLDSA44_MAX_KEYS) return std::nullopt;
    if (threshold < 1 || threshold > count) return std::nullopt;
    std::vector<uint256> ordered(key_hashes.begin(), key_hashes.end());
    std::sort(ordered.begin(), ordered.end());
    for (std::size_t i{1}; i < ordered.size(); ++i) {
        if (!(ordered[i - 1] < ordered[i])) return std::nullopt;
    }
    std::vector<unsigned char> preimage;
    preimage.reserve(1 + 18 + 2 + count * 32);
    preimage.push_back(0x12);
    const std::string tag{"FCN-MLDSA44-POLICY"};
    preimage.insert(preimage.end(), tag.begin(), tag.end());
    preimage.push_back(threshold);
    preimage.push_back(static_cast<unsigned char>(count));
    for (const uint256& hash : ordered) {
        preimage.insert(preimage.end(), hash.begin(), hash.end());
    }
    uint256 program;
    if (!Blake2b256(preimage, program)) return std::nullopt;
    return program;
}

bool CheckSingleKeySpend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    if (witness.size() != 2) return false;
    if (witness[0].size() != MLDSA44_PUBLIC_KEY_SIZE) return false;
    if (witness[1].size() != MLDSA44_SIGNATURE_SIZE) return false;
    if (MlDsa44SingleKeyProgram(witness[0]) != program) return false;
    return MlDsa44Verify(witness[0], witness[1], sighash);
}

namespace {

struct ParsedSlot {
    uint256 hash;
    bool signed_slot{false};
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> signature;
};

struct ParsedSlots {
    std::vector<ParsedSlot> slots;
    int signed_ok{0};
    bool ok{false};
};

ParsedSlots ParseSlots(const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash, bool verify_signatures)
{
    ParsedSlots parsed;
    std::size_t i{0};
    while (i < witness.size()) {
        const std::vector<unsigned char>& item{witness[i]};
        if (item.size() == 32) {
            ParsedSlot slot;
            slot.hash = uint256{Span<const unsigned char>{item.data(), item.size()}};
            parsed.slots.push_back(std::move(slot));
            ++i;
            continue;
        }
        if (item.size() != MLDSA44_PUBLIC_KEY_SIZE) return parsed;
        if (i + 1 >= witness.size()) return parsed;
        const std::vector<unsigned char>& signature{witness[i + 1]};
        if (signature.size() != MLDSA44_SIGNATURE_SIZE) return parsed;
        if (verify_signatures) {
            if (!MlDsa44Verify(item, signature, sighash)) return parsed;
        }
        ParsedSlot slot;
        slot.hash = MlDsa44KeyHash(item);
        slot.signed_slot = true;
        slot.pubkey = item;
        slot.signature = signature;
        parsed.slots.push_back(std::move(slot));
        ++parsed.signed_ok;
        i += 2;
    }
    parsed.ok = i == witness.size() && parsed.slots.size() >= 1 && parsed.slots.size() <= MLDSA44_MAX_KEYS;
    return parsed;
}

} // namespace

bool CheckMultisigSpend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    const ParsedSlots parsed{ParseSlots(witness, sighash, /*verify_signatures=*/true)};
    if (!parsed.ok) return false;
    for (std::size_t h{1}; h < parsed.slots.size(); ++h) {
        if (!(parsed.slots[h - 1].hash < parsed.slots[h].hash)) return false;
    }
    std::vector<uint256> hashes;
    hashes.reserve(parsed.slots.size());
    for (const ParsedSlot& slot : parsed.slots) hashes.push_back(slot.hash);
    const uint8_t count{static_cast<uint8_t>(hashes.size())};
    for (uint8_t threshold{1}; threshold <= count; ++threshold) {
        const std::optional<uint256> expected{MlDsa44PolicyProgram(threshold, hashes)};
        if (expected && *expected == program) {
            return parsed.signed_ok >= threshold;
        }
    }
    return false;
}

std::optional<std::vector<std::vector<unsigned char>>> MergeMlDsa44Witnesses(
    const std::vector<std::vector<std::vector<unsigned char>>>& stacks,
    std::span<const unsigned char> sighash)
{
    const bool verify{sighash.size() == 32};
    std::vector<ParsedSlot> merged;
    bool have{false};
    for (const auto& stack : stacks) {
        const ParsedSlots parsed{ParseSlots(stack, sighash, verify)};
        if (!parsed.ok) continue;
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
    for (const ParsedSlot& slot : merged) {
        if (slot.signed_slot) {
            out.push_back(slot.pubkey);
            out.push_back(slot.signature);
        } else {
            out.emplace_back(slot.hash.begin(), slot.hash.end());
        }
    }
    return out;
}

MlDsaSpendKind MlDsaSpendKindOf(const std::vector<std::vector<unsigned char>>& witness)
{
    if (witness.size() == 2 && witness[0].size() == MLDSA44_PUBLIC_KEY_SIZE && witness[1].size() == MLDSA44_SIGNATURE_SIZE) {
        return MlDsaSpendKind::Single;
    }
    static constexpr unsigned char none[]{0};
    const ParsedSlots parsed{ParseSlots(witness, std::span<const unsigned char>{none, 0}, /*verify_signatures=*/false)};
    if (parsed.ok) return MlDsaSpendKind::Multi;
    return MlDsaSpendKind::Absent;
}

} // namespace Consensus
