// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/witness_spend_kind.h>

#include <consensus/mldsa44_spend.h>
#include <policy/settings.h>
#include <consensus/mldsa87_spend.h>
#include <consensus/secp_spend.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <serialize.h>
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

bool ApplyWitnessSizeCap(const CTxIn& txin,
                         const std::string& reason_prefix,
                         std::string& out_reason,
                         const ignore_rejects_type& ignore_rejects)
{
    if (GetSerializeSize(txin.scriptWitness.stack) > g_script_size_policy_limit) {
        if (RejectIfNotIgnored(out_reason, "witness-size", reason_prefix, ignore_rejects)) {
            return false;
        }
    }
    return true;
}

bool MatchesP2WPKH(int witnessversion, size_t program_size, const std::vector<std::vector<unsigned char>>& stack)
{
    return witnessversion == 0 && program_size == WITNESS_V0_KEYHASH_SIZE && Consensus::IsSecpSingleWitness(stack);
}

bool MatchesMlDsa44(int witnessversion, size_t program_size, const std::vector<std::vector<unsigned char>>& stack)
{
    return witnessversion == 0 && program_size == WITNESS_V0_SCRIPTHASH_SIZE &&
           Consensus::ClassifyMlDsa44Witness(stack) != Consensus::MlDsa44WitnessLayout::Neither;
}

bool MatchesMlDsa87(int witnessversion, size_t program_size, const std::vector<std::vector<unsigned char>>& stack)
{
    return witnessversion == 0 && program_size == WITNESS_V0_SCRIPTHASH_SIZE &&
           Consensus::ClassifyMlDsa87Witness(stack) != Consensus::MlDsa87WitnessLayout::Neither;
}

bool MatchesLeftoverV0ScriptHash(int witnessversion, size_t program_size)
{
    return witnessversion == 0 && program_size == WITNESS_V0_SCRIPTHASH_SIZE;
}

bool MatchesTaproot(int witnessversion, size_t program_size, bool p2sh)
{
    return witnessversion == 1 && program_size == WITNESS_V1_TAPROOT_SIZE && !p2sh;
}

bool ApplyLeftoverV0ScriptHash(const CTxIn& txin,
                               const std::string& reason_prefix,
                               std::string& out_reason,
                               const ignore_rejects_type& ignore_rejects)
{
    if (!ApplyWitnessSizeCap(txin, reason_prefix, out_reason, ignore_rejects)) {
        return false;
    }
    const auto& stack = txin.scriptWitness.stack;
    if (stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE) {
        if (RejectIfNotIgnored(out_reason, "script-size", reason_prefix, ignore_rejects)) {
            return false;
        }
    }
    const size_t sizeWitnessStack = stack.size() - 1;
    if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS) {
        if (RejectIfNotIgnored(out_reason, "stackitem-count", reason_prefix, ignore_rejects)) {
            return false;
        }
    }
    for (size_t j = 0; j < sizeWitnessStack; j++) {
        if (stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE) {
            if (RejectIfNotIgnored(out_reason, "stackitem-size", reason_prefix, ignore_rejects)) {
                return false;
            }
        }
    }
    return true;
}

bool ApplyTaproot(const CTxIn& txin,
                  const std::string& reason_prefix,
                  std::string& out_reason,
                  const ignore_rejects_type& ignore_rejects)
{
    if (!ApplyWitnessSizeCap(txin, reason_prefix, out_reason, ignore_rejects)) {
        return false;
    }
    Span stack{txin.scriptWitness.stack};
    if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
        if (RejectIfNotIgnored(out_reason, "taproot-annex", reason_prefix, ignore_rejects)) {
            return false;
        }
        SpanPopBack(stack);
    }
    if (stack.size() >= 2) {
        const auto& control_block = SpanPopBack(stack);
        SpanPopBack(stack);
        if (control_block.empty()) {
            out_reason = reason_prefix + "taproot-control-missing";
            return false;
        }
        if ((control_block[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT) {
            if (!ignore_rejects.count(reason_prefix + "taproot-stackitem-size")) {
                for (const auto& item : stack) {
                    if (item.size() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE) {
                        out_reason = reason_prefix + "taproot-stackitem-size";
                        return false;
                    }
                }
            }
        }
    } else if (stack.size() == 1) {
    } else {
        out_reason = reason_prefix + "taproot-witness-missing";
        return false;
    }
    return true;
}

std::pair<CScript, unsigned int> ExtractLeftoverV0ScriptHash(const CTxIn& txin)
{
    Span stack{txin.scriptWitness.stack};
    if (stack.empty()) return std::make_pair(CScript(), 0);
    auto& script_data = stack.back();
    return std::make_pair(CScript(script_data.begin(), script_data.end()), 1);
}

std::pair<CScript, unsigned int> ExtractTaproot(const CTxIn& txin)
{
    Span stack{txin.scriptWitness.stack};
    if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
        SpanPopBack(stack);
    }
    if (stack.size() >= 2) {
        SpanPopBack(stack);
        return std::make_pair(CScript(stack.back().begin(), stack.back().end()), 1);
    }
    return std::make_pair(CScript(), 0);
}

} // namespace

std::optional<PolicyWitnessKind> MatchPolicyWitnessKind(int witnessversion,
                                                       size_t program_size,
                                                       const std::vector<std::vector<unsigned char>>& stack,
                                                       bool p2sh)
{
    if (MatchesP2WPKH(witnessversion, program_size, stack)) return PolicyWitnessKind::P2WPKH;
    if (MatchesMlDsa44(witnessversion, program_size, stack)) return PolicyWitnessKind::MlDsa44;
    if (MatchesMlDsa87(witnessversion, program_size, stack)) return PolicyWitnessKind::MlDsa87;
    if (MatchesLeftoverV0ScriptHash(witnessversion, program_size)) return PolicyWitnessKind::LeftoverV0ScriptHash;
    if (MatchesTaproot(witnessversion, program_size, p2sh)) return PolicyWitnessKind::Taproot;
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
    case PolicyWitnessKind::P2WPKH:
    case PolicyWitnessKind::MlDsa44:
    case PolicyWitnessKind::MlDsa87:
        return true;
    case PolicyWitnessKind::LeftoverV0ScriptHash:
        return ApplyLeftoverV0ScriptHash(txin, reason_prefix, out_reason, ignore_rejects);
    case PolicyWitnessKind::Taproot:
        return ApplyTaproot(txin, reason_prefix, out_reason, ignore_rejects);
    }
    return false;
}

std::pair<CScript, unsigned int> ExtractPolicyWitnessScript(PolicyWitnessKind kind,
                                                           const CTxIn& txin,
                                                           bool)
{
    switch (kind) {
    case PolicyWitnessKind::P2WPKH:
    case PolicyWitnessKind::MlDsa44:
    case PolicyWitnessKind::MlDsa87:
        return std::make_pair(CScript(), 0);
    case PolicyWitnessKind::LeftoverV0ScriptHash:
        return ExtractLeftoverV0ScriptHash(txin);
    case PolicyWitnessKind::Taproot:
        return ExtractTaproot(txin);
    }
    return std::make_pair(CScript(), 0);
}
