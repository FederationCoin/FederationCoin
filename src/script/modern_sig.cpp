// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/modern_sig.h>

#include <consensus/mldsa44_spend.h>
#include <consensus/mldsa87_spend.h>
#include <consensus/mldsa_fingerprint.h>

#include <algorithm>
#include <cassert>

namespace {

bool HashesStrictlyIncreasing(std::span<const uint256> hashes)
{
    for (std::size_t i{1}; i < hashes.size(); ++i) {
        if (!(hashes[i - 1] < hashes[i])) return false;
    }
    return true;
}

bool SmallIntOpcode(opcodetype opcode, int32_t min_v, int32_t max_v, int32_t& out)
{
    if (opcode < OP_1 || opcode > OP_16) return false;
    const int32_t v{CScript::DecodeOP_N(opcode)};
    if (v < min_v || v > max_v) return false;
    out = v;
    return true;
}

bool Minimal32Push(opcodetype opcode, const std::vector<unsigned char>& data, uint256& out)
{
    if (opcode != 0x20 || data.size() != 32) return false;
    out = uint256{Span<const unsigned char>{data.data(), data.size()}};
    return true;
}

template <typename SpendKind>
class DilithiumModernKind final : public ModernSigKind
{
public:
    std::size_t PubkeySize() const override { return SpendKind::PUBKEY_SIZE; }
    std::size_t SignatureSize() const override { return SpendKind::SIGNATURE_SIZE; }
    std::size_t CombinedWitnessSize() const override { return SpendKind::PUBKEY_SIZE + SpendKind::SIGNATURE_SIZE; }
    std::size_t MaxKeys() const override { return SpendKind::MAX_KEYS; }
    std::size_t MaxStackElement() const override
    {
        const std::size_t combined{SpendKind::PUBKEY_SIZE + SpendKind::SIGNATURE_SIZE};
        return std::max(combined, std::max(SpendKind::PUBKEY_SIZE, SpendKind::SIGNATURE_SIZE));
    }
    bool KeyFingerprint(std::span<const unsigned char> pubkey, uint256& out) const override
    {
        const std::optional<uint256> hash{Consensus::MlDsaTaggedKeyHash<SpendKind>(pubkey)};
        if (!hash) return false;
        out = *hash;
        return true;
    }
    bool Verify(std::span<const unsigned char> pubkey,
                std::span<const unsigned char> signature,
                std::span<const unsigned char> message) const override
    {
        return SpendKind::Verify(pubkey, signature, message);
    }
    bool VerifySingle(const uint256& fingerprint,
                      const std::vector<std::vector<unsigned char>>& witness,
                      std::span<const unsigned char> message) const override
    {
        if (witness.size() != 2) return false;
        if (witness[0].size() != SpendKind::PUBKEY_SIZE) return false;
        if (witness[1].size() != SpendKind::SIGNATURE_SIZE) return false;
        uint256 hash;
        if (!KeyFingerprint(witness[0], hash) || hash != fingerprint) return false;
        return SpendKind::Verify(witness[0], witness[1], message);
    }
    bool VerifyPolicy(uint8_t threshold,
                      std::span<const uint256> hashes,
                      const std::vector<std::vector<unsigned char>>& witness,
                      std::span<const unsigned char> message) const override
    {
        const std::size_t n{hashes.size()};
        if (n < 1 || n > SpendKind::MAX_KEYS) return false;
        if (threshold < 1 || threshold > n) return false;
        if (witness.size() != n) return false;
        if (!HashesStrictlyIncreasing(hashes)) return false;
        int signed_ok{0};
        for (std::size_t i{0}; i < n; ++i) {
            const std::vector<unsigned char>& item{witness[i]};
            if (item.empty()) continue;
            if (item.size() != CombinedWitnessSize()) return false;
            const std::span<const unsigned char> pubkey{item.data(), SpendKind::PUBKEY_SIZE};
            const std::span<const unsigned char> signature{item.data() + SpendKind::PUBKEY_SIZE, SpendKind::SIGNATURE_SIZE};
            uint256 hash;
            if (!KeyFingerprint(pubkey, hash) || hash != hashes[i]) return false;
            if (!SpendKind::Verify(pubkey, signature, message)) return false;
            ++signed_ok;
        }
        return signed_ok >= threshold;
    }
};

const DilithiumModernKind<Consensus::MlDsa44Kind> g_dilithium_44;
const DilithiumModernKind<Consensus::MlDsa87Kind> g_dilithium_87;

struct RegistryRow {
    int32_t algorithm;
    int32_t param;
    const ModernSigKind* kind;
};

const RegistryRow g_registry[] = {
    {ALGO_DILITHIUM, PARAM_DILITHIUM_44, &g_dilithium_44},
    {ALGO_DILITHIUM, PARAM_DILITHIUM_87, &g_dilithium_87},
};

} // namespace

const ModernSigKind* LookupModernSigKind(int32_t algorithm, int32_t param)
{
    for (const RegistryRow& row : g_registry) {
        if (row.algorithm == algorithm && row.param == param) return row.kind;
    }
    return nullptr;
}

std::optional<ModernSingleParsed> MatchModernSingle(const CScript& script)
{
    CScript::const_iterator it{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    ModernSingleParsed parsed;
    if (!script.GetOp(it, opcode, data) || !Minimal32Push(opcode, data, parsed.fingerprint)) return std::nullopt;
    if (!script.GetOp(it, opcode, data) || !SmallIntOpcode(opcode, 1, 16, parsed.algorithm)) return std::nullopt;
    if (!script.GetOp(it, opcode, data) || !SmallIntOpcode(opcode, 1, 16, parsed.param)) return std::nullopt;
    if (!script.GetOp(it, opcode, data) || opcode != OP_CHECKMODERNSIG) return std::nullopt;
    if (it != script.end()) return std::nullopt;
    parsed.kind = LookupModernSigKind(parsed.algorithm, parsed.param);
    return parsed;
}

std::optional<ModernPolicyParsed> MatchModernPolicy(const CScript& script)
{
    CScript::const_iterator it{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    ModernPolicyParsed parsed;
    int32_t t{0};
    if (!script.GetOp(it, opcode, data) || !SmallIntOpcode(opcode, 1, MODERN_POLICY_MAX_KEYS, t)) return std::nullopt;
    parsed.threshold = static_cast<uint8_t>(t);
    while (true) {
        CScript::const_iterator mark{it};
        if (!script.GetOp(it, opcode, data)) return std::nullopt;
        uint256 hash;
        if (Minimal32Push(opcode, data, hash)) {
            parsed.hashes.push_back(hash);
            if (parsed.hashes.size() > MODERN_POLICY_MAX_KEYS) return std::nullopt;
            continue;
        }
        it = mark;
        break;
    }
    int32_t n{0};
    if (!script.GetOp(it, opcode, data) || !SmallIntOpcode(opcode, 1, MODERN_POLICY_MAX_KEYS, n)) return std::nullopt;
    parsed.n = static_cast<uint8_t>(n);
    if (parsed.hashes.size() != static_cast<std::size_t>(parsed.n)) return std::nullopt;
    if (parsed.threshold > parsed.n) return std::nullopt;
    if (!HashesStrictlyIncreasing(parsed.hashes)) return std::nullopt;
    if (!script.GetOp(it, opcode, data) || !SmallIntOpcode(opcode, 1, 16, parsed.algorithm)) return std::nullopt;
    if (!script.GetOp(it, opcode, data) || !SmallIntOpcode(opcode, 1, 16, parsed.param)) return std::nullopt;
    if (!script.GetOp(it, opcode, data) || opcode != OP_CHECKMODERNPOLICY) return std::nullopt;
    if (it != script.end()) return std::nullopt;
    parsed.kind = LookupModernSigKind(parsed.algorithm, parsed.param);
    return parsed;
}

bool IsModernSigTemplate(const CScript& script)
{
    return MatchModernSingle(script).has_value() || MatchModernPolicy(script).has_value();
}

CScript BuildModernSingle(const uint256& fingerprint, int32_t algorithm, int32_t param)
{
    CScript script;
    script << std::vector<unsigned char>(fingerprint.begin(), fingerprint.end());
    script << CScript::EncodeOP_N(algorithm);
    script << CScript::EncodeOP_N(param);
    script << OP_CHECKMODERNSIG;
    return script;
}

std::optional<CScript> BuildModernPolicy(uint8_t threshold, std::span<const uint256> key_hashes, int32_t algorithm, int32_t param)
{
    const std::size_t count{key_hashes.size()};
    if (count < 1 || count > MODERN_POLICY_MAX_KEYS) return std::nullopt;
    if (threshold < 1 || threshold > count) return std::nullopt;
    std::vector<uint256> ordered(key_hashes.begin(), key_hashes.end());
    std::sort(ordered.begin(), ordered.end());
    if (!HashesStrictlyIncreasing(ordered)) return std::nullopt;
    CScript script;
    script << CScript::EncodeOP_N(threshold);
    for (const uint256& hash : ordered) {
        script << std::vector<unsigned char>(hash.begin(), hash.end());
    }
    script << CScript::EncodeOP_N(static_cast<int>(count));
    script << CScript::EncodeOP_N(algorithm);
    script << CScript::EncodeOP_N(param);
    script << OP_CHECKMODERNPOLICY;
    return script;
}
