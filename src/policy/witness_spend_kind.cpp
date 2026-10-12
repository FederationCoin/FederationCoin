// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/witness_spend_kind.h>

#include <consensus/mldsa44_spend.h>
#include <consensus/mldsa87_spend.h>
#include <consensus/secp_spend.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
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

bool MatchesTaproot(int witnessversion, size_t program_size, bool p2sh)
{
    return witnessversion == 1 && program_size == WITNESS_V1_TAPROOT_SIZE && !p2sh;
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
    if (MatchesTaproot(witnessversion, program_size, p2sh)) return PolicyWitnessKind::Taproot;
    return std::nullopt;
}

bool ApplyPolicyWitnessKind(PolicyWitnessKind kind,
                            const CTxIn&,
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
