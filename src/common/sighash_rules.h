// Copyright (c) 2026-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_SIGHASH_RULES_H
#define BITCOIN_COMMON_SIGHASH_RULES_H

#include <script/interpreter.h>

class ArgsManager;
namespace Consensus {
struct Params;
}

void SetupSighashRulesArgs(ArgsManager& argsman);

/** Signing is always the unified message. There is no compatibility window. */
SighashRules SighashRulesForSigning(const ArgsManager& args, const Consensus::Params& params);

/** Verify under the unified rules. CScriptCheck only accepts UNIFIED. */
SighashRules SighashRulesForVerifying();

/** The same rule, read from the active chain parameters and the command line.
 *
 * Every signer wants this same answer, so it is read where the signature is made
 * rather than threaded down from each caller. Not usable before SelectParams(),
 * which rules out static initializers. */
SighashRules SighashRulesForSigning();

#endif // BITCOIN_COMMON_SIGHASH_RULES_H
