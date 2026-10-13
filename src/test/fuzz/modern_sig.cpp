// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/modern_sig.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <cassert>
#include <span>
#include <vector>

namespace {

class FuzzUnifiedChecker final : public BaseSignatureChecker
{
    uint256 m_hash;
public:
    explicit FuzzUnifiedChecker(uint256 hash) : m_hash(hash) {}
    bool GetUnifiedSighash(uint256& hash_out) const override
    {
        hash_out = m_hash;
        return true;
    }
};

CScriptWitness ConsumeWitness(FuzzedDataProvider& provider, std::size_t n, std::size_t max_elem)
{
    CScriptWitness witness;
    witness.stack.reserve(n);
    for (std::size_t i{0}; i < n; ++i) {
        witness.stack.push_back(ConsumeRandomLengthByteVector(provider, max_elem));
    }
    return witness;
}

} // namespace

FUZZ_TARGET(modern_sig)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const CScript script{ConsumeScript(provider, /*maybe_p2wsh=*/provider.ConsumeBool())};
    const auto single{MatchModernSingle(script)};
    const auto policy{MatchModernPolicy(script)};
    assert(!(single.has_value() && policy.has_value()));
    assert(IsModernSigTemplate(script) == (single.has_value() || policy.has_value()));

    if (single) {
        assert(LookupModernSigKind(single->algorithm, single->param) == single->kind);
        const CScript rebuilt{BuildModernSingle(single->fingerprint, single->algorithm, single->param)};
        assert(rebuilt == script);
    }
    if (policy) {
        assert(LookupModernSigKind(policy->algorithm, policy->param) == policy->kind);
        const auto rebuilt{BuildModernPolicy(policy->threshold, policy->hashes, policy->algorithm, policy->param)};
        assert(rebuilt.has_value() && *rebuilt == script);
    }

    const uint256 fingerprint{ConsumeUInt256(provider)};
    const int32_t algorithm{provider.ConsumeIntegralInRange<int32_t>(1, 16)};
    const int32_t param{provider.ConsumeIntegralInRange<int32_t>(1, 16)};
    const CScript built_single{BuildModernSingle(fingerprint, algorithm, param)};
    const auto matched_single{MatchModernSingle(built_single)};
    assert(matched_single.has_value());
    assert(matched_single->fingerprint == fingerprint);
    assert(matched_single->algorithm == algorithm);
    assert(matched_single->param == param);
    assert(matched_single->kind == LookupModernSigKind(algorithm, param));

    std::vector<unsigned char> pushdata1;
    pushdata1.push_back(OP_PUSHDATA1);
    pushdata1.push_back(32);
    pushdata1.insert(pushdata1.end(), fingerprint.begin(), fingerprint.end());
    pushdata1.push_back(OP_1);
    pushdata1.push_back(OP_1);
    pushdata1.push_back(OP_CHECKMODERNSIG);
    const CScript pushdata_script{pushdata1.begin(), pushdata1.end()};
    assert(!MatchModernSingle(pushdata_script));

    const uint8_t n{provider.ConsumeIntegralInRange<uint8_t>(1, MODERN_POLICY_MAX_KEYS)};
    const uint8_t threshold{provider.ConsumeIntegralInRange<uint8_t>(1, n)};
    std::vector<uint256> hashes;
    hashes.reserve(n);
    for (uint8_t i{0}; i < n; ++i) {
        hashes.push_back(ConsumeUInt256(provider));
    }
    const auto built_policy{BuildModernPolicy(threshold, hashes, algorithm, param)};
    if (built_policy) {
        const auto matched_policy{MatchModernPolicy(*built_policy)};
        assert(matched_policy.has_value());
        assert(matched_policy->threshold == threshold);
        assert(matched_policy->n == n);
        assert(matched_policy->kind == LookupModernSigKind(algorithm, param));
    }

    const uint256 sighash{ConsumeUInt256(provider)};
    FuzzUnifiedChecker checker{sighash};
    const unsigned flags{SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_UNIFIED_SIGHASH | SCRIPT_VERIFY_MINIMALDATA};
    CScript script_sig;
    if (provider.ConsumeBool()) {
        script_sig << provider.ConsumeIntegral<uint8_t>();
    }
    CScriptWitness witness{ConsumeWitness(provider, provider.ConsumeIntegralInRange<std::size_t>(0, 16), 8000)};
    ScriptError serror{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool ok{VerifyScript(script_sig, built_single, &witness, flags, checker, &serror)};
    assert(ok == (serror == SCRIPT_ERR_OK));
    if (!script_sig.empty()) {
        assert(!ok);
        assert(serror == SCRIPT_ERR_WITNESS_MALLEATED);
    } else if (!matched_single->kind) {
        assert(!ok);
        assert(serror == SCRIPT_ERR_EVAL_FALSE);
    }

    if (single && single->kind) {
        std::vector<std::vector<unsigned char>> kind_wit;
        kind_wit.push_back(ConsumeRandomLengthByteVector(provider, 8000));
        kind_wit.push_back(ConsumeRandomLengthByteVector(provider, 8000));
        (void)single->kind->VerifySingle(single->fingerprint, kind_wit, std::span<const unsigned char>{sighash.begin(), 32});
    }
    if (policy && policy->kind) {
        std::vector<std::vector<unsigned char>> kind_wit;
        kind_wit.reserve(policy->n);
        for (uint8_t i{0}; i < policy->n; ++i) {
            kind_wit.push_back(ConsumeRandomLengthByteVector(provider, 8000));
        }
        (void)policy->kind->VerifyPolicy(policy->threshold, policy->hashes, kind_wit, std::span<const unsigned char>{sighash.begin(), 32});
    }
}
