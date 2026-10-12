// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_WITNESS_SPEND_KIND_H
#define BITCOIN_POLICY_WITNESS_SPEND_KIND_H

#include <policy/policy.h>
#include <script/script.h>

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class CTxIn;

/** Closed set of policy witness kinds. Standardness, not flex weight. */
enum class PolicyWitnessKind {
    P2WPKH,
    MlDsa44,
    MlDsa87,
    Taproot,
};

/** First matching kind for this program version/length and witness stack.
 *  Nullopt when no named kind claims the envelope. Unmatched v0/32 is
 *  nonstandard (not leftover Bitcoin P2WSH). Taproot matches so Apply can
 *  fail closed while the interpreter is parked. */
std::optional<PolicyWitnessKind> MatchPolicyWitnessKind(int witnessversion,
                                                       size_t program_size,
                                                       const std::vector<std::vector<unsigned char>>& stack,
                                                       bool p2sh);

/** Kind-owned standardness. True when the input is standard (or ignored). */
bool ApplyPolicyWitnessKind(PolicyWitnessKind kind,
                            const CTxIn& txin,
                            bool p2sh,
                            const std::string& reason_prefix,
                            std::string& out_reason,
                            const ignore_rejects_type& ignore_rejects);

/** Kind-owned script extraction for datacarrier accounting. */
std::pair<CScript, unsigned int> ExtractPolicyWitnessScript(PolicyWitnessKind kind,
                                                           const CTxIn& txin,
                                                           bool p2sh);

#endif // BITCOIN_POLICY_WITNESS_SPEND_KIND_H
