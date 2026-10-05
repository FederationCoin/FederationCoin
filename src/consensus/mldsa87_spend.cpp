// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa87_spend.h>

#include <crypto/blake2b.h>
#include <span.h>

#include <algorithm>
#include <string>

extern "C" {
#include <crypto/mldsa87/api.h>
void mldsa87_use_seed(const uint8_t* seed, size_t len);
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

bool MlDsa87Keygen(std::span<const unsigned char> seed, MlDsa87Keypair& out)
{
    if (seed.size() != MLDSA87_SEED_SIZE) return false;
    mldsa87_use_seed(seed.data(), seed.size());
    const int rc{PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(out.pubkey.data(), out.secret.data())};
    mldsa87_use_seed(nullptr, 0);
    return rc == 0;
}

bool MlDsa87Sign(const MlDsa87Keypair& key, std::span<const unsigned char> message, std::span<unsigned char> signature)
{
    if (signature.size() != MLDSA87_SIGNATURE_SIZE) return false;
    static constexpr char context[]{"FederationCoin"};
    size_t siglen{0};
    const int rc{PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx(signature.data(), &siglen, message.data(), message.size(), reinterpret_cast<const uint8_t*>(context), sizeof(context) - 1, key.secret.data())};
    return rc == 0 && siglen == MLDSA87_SIGNATURE_SIZE;
}

bool MlDsa87Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message)
{
    if (pubkey.size() != MLDSA87_PUBLIC_KEY_SIZE) return false;
    if (signature.size() != MLDSA87_SIGNATURE_SIZE) return false;
    static constexpr char context[]{"FederationCoin"};
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(signature.data(), signature.size(), message.data(), message.size(), reinterpret_cast<const uint8_t*>(context), sizeof(context) - 1, pubkey.data()) == 0;
}

uint256 MlDsa87KeyHash(std::span<const unsigned char> pubkey)
{
    uint256 hash;
    if (pubkey.size() != MLDSA87_PUBLIC_KEY_SIZE) return hash;
    std::vector<unsigned char> preimage;
    preimage.reserve(1 + 15 + MLDSA87_PUBLIC_KEY_SIZE);
    preimage.push_back(0x0f);
    const std::string tag{"FCN-MLDSA87-KEY"};
    preimage.insert(preimage.end(), tag.begin(), tag.end());
    preimage.insert(preimage.end(), pubkey.begin(), pubkey.end());
    Blake2b256(preimage, hash);
    return hash;
}

uint256 MlDsa87SingleKeyProgram(std::span<const unsigned char> pubkey)
{
    return MlDsa87KeyHash(pubkey);
}

std::optional<uint256> MlDsa87PolicyProgram(uint8_t threshold, std::span<const uint256> key_hashes)
{
    const std::size_t count{key_hashes.size()};
    if (count < 1 || count > MLDSA87_MAX_KEYS) return std::nullopt;
    if (threshold < 1 || threshold > count) return std::nullopt;
    std::vector<uint256> ordered(key_hashes.begin(), key_hashes.end());
    std::sort(ordered.begin(), ordered.end());
    for (std::size_t i{1}; i < ordered.size(); ++i) {
        if (!(ordered[i - 1] < ordered[i])) return std::nullopt;
    }
    std::vector<unsigned char> preimage;
    preimage.reserve(1 + 18 + 2 + count * 32);
    preimage.push_back(0x12);
    const std::string tag{"FCN-MLDSA87-POLICY"};
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

bool CheckSingleKey87Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    if (witness.size() != 2) return false;
    if (witness[0].size() != MLDSA87_PUBLIC_KEY_SIZE) return false;
    if (witness[1].size() != MLDSA87_SIGNATURE_SIZE) return false;
    if (MlDsa87SingleKeyProgram(witness[0]) != program) return false;
    return MlDsa87Verify(witness[0], witness[1], sighash);
}

namespace {

struct ParsedSlots87 {
    std::vector<uint256> hashes;
    int signed_ok{0};
    bool ok{false};
};

ParsedSlots87 ParseSlots87(const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash, bool verify_signatures)
{
    ParsedSlots87 parsed;
    std::size_t i{0};
    while (i < witness.size()) {
        const std::vector<unsigned char>& item{witness[i]};
        if (item.size() == 32) {
            parsed.hashes.emplace_back(Span<const unsigned char>{item.data(), item.size()});
            ++i;
            continue;
        }
        if (item.size() != MLDSA87_PUBLIC_KEY_SIZE) return parsed;
        if (i + 1 >= witness.size()) return parsed;
        const std::vector<unsigned char>& signature{witness[i + 1]};
        if (signature.size() != MLDSA87_SIGNATURE_SIZE) return parsed;
        parsed.hashes.push_back(MlDsa87KeyHash(item));
        if (verify_signatures) {
            if (!MlDsa87Verify(item, signature, sighash)) return parsed;
        }
        ++parsed.signed_ok;
        i += 2;
    }
    parsed.ok = i == witness.size() && parsed.hashes.size() >= 1 && parsed.hashes.size() <= MLDSA87_MAX_KEYS;
    return parsed;
}

} // namespace

bool CheckMultisig87Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    const ParsedSlots87 parsed{ParseSlots87(witness, sighash, /*verify_signatures=*/true)};
    if (!parsed.ok) return false;
    for (std::size_t h{1}; h < parsed.hashes.size(); ++h) {
        if (!(parsed.hashes[h - 1] < parsed.hashes[h])) return false;
    }
    const uint8_t count{static_cast<uint8_t>(parsed.hashes.size())};
    for (uint8_t threshold{1}; threshold <= count; ++threshold) {
        const std::optional<uint256> expected{MlDsa87PolicyProgram(threshold, parsed.hashes)};
        if (expected && *expected == program) {
            return parsed.signed_ok >= threshold;
        }
    }
    return false;
}

MlDsa87SpendKind MlDsa87SpendKindOf(const std::vector<std::vector<unsigned char>>& witness)
{
    if (witness.size() == 2 && witness[0].size() == MLDSA87_PUBLIC_KEY_SIZE && witness[1].size() == MLDSA87_SIGNATURE_SIZE) {
        return MlDsa87SpendKind::Single;
    }
    static constexpr unsigned char none[]{0};
    const ParsedSlots87 parsed{ParseSlots87(witness, std::span<const unsigned char>{none, 0}, /*verify_signatures=*/false)};
    if (parsed.ok) return MlDsa87SpendKind::Multi;
    return MlDsa87SpendKind::Absent;
}

} // namespace Consensus
