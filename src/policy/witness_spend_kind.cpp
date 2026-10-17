// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/witness_spend_kind.h>

#include <consensus/secp_spend.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/modern_sig.h>
#include <span.h>

#include <vector>

namespace {

bool RejectIfNotIgnored(std::string& out_reason,
                        const std::string& reason,
                        const std::string& reason_prefix,
                        const ignore_rejects_type& ignore_rejects)
{
    out_reason = reason_prefix + reason;
    return !ignore_rejects.count(out_reason);
}

std::optional<PolicyWitnessKind> KindFromModern(const ModernSigKind* kind)
{
    if (kind == LookupModernSigKind(ALGO_DILITHIUM, PARAM_DILITHIUM_44)) return PolicyWitnessKind::MlDsa44;
    if (kind == LookupModernSigKind(ALGO_DILITHIUM, PARAM_DILITHIUM_87)) return PolicyWitnessKind::MlDsa87;
    return std::nullopt;
}

} // namespace

std::optional<PolicyWitnessKind> MatchPolicyWitnessKind(const CScript& scriptPubKey,
                                                       const std::vector<std::vector<unsigned char>>& stack,
                                                       bool p2sh)
{
    int witnessversion{0};
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_KEYHASH_SIZE && Consensus::IsSecpSingleWitness(stack)) {
            return PolicyWitnessKind::P2WPKH;
        }
        if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
            return PolicyWitnessKind::Taproot;
        }
        return std::nullopt;
    }
    if (const auto single{MatchModernSingle(scriptPubKey)}; single && single->kind) {
        return KindFromModern(single->kind);
    }
    if (const auto policy{MatchModernPolicy(scriptPubKey)}; policy && policy->kind) {
        return KindFromModern(policy->kind);
    }
    return std::nullopt;
}

bool ApplyPolicyWitnessKind(PolicyWitnessKind kind,
                            const CTxIn& txin,
                            bool,
                            const std::string& reason_prefix,
                            std::string& out_reason,
                            const ignore_rejects_type& ignore_rejects)
{
    switch (kind) {
    case PolicyWitnessKind::P2WPKH: {
        const auto& stack = txin.scriptWitness.stack;
        if (stack.empty() ||
            !CheckSignatureEncoding(stack[0],
                                    SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_UNIFIED_SIGHASH,
                                    nullptr)) {
            if (RejectIfNotIgnored(out_reason, "low_s", reason_prefix, ignore_rejects)) {
                return false;
            }
        }
        return true;
    }
    case PolicyWitnessKind::MlDsa44:
    case PolicyWitnessKind::MlDsa87:
        return true;
    case PolicyWitnessKind::Taproot:
        if (RejectIfNotIgnored(out_reason, "taproot", reason_prefix, ignore_rejects)) {
            return false;
        }
        return true;
    }
    return false;
}

std::pair<CScript, unsigned int> ExtractPolicyWitnessScript(PolicyWitnessKind kind,
                                                           const CTxIn&,
                                                           bool)
{
    switch (kind) {
    case PolicyWitnessKind::P2WPKH:
    case PolicyWitnessKind::MlDsa44:
    case PolicyWitnessKind::MlDsa87:
    case PolicyWitnessKind::Taproot:
        return std::make_pair(CScript(), 0);
    }
    return std::make_pair(CScript(), 0);
}
