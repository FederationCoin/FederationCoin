// Copyright (c) 2026-present The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/sighash_rules.h>

#include <chainparams.h>
#include <common/args.h>
#include <consensus/params.h>
#include <deploymentstatus.h>
#include <util/translation.h>

SighashRules SighashRulesForSigning(const ArgsManager&, const Consensus::Params&)
{
    return SighashRules::UNIFIED;
}

SighashRules SighashRulesForSigning()
{
    return SighashRulesForSigning(gArgs, Params().GetConsensus());
}

SighashRules SighashRulesForVerifying()
{
    return SighashRules::UNIFIED;
}
