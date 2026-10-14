// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/work/kind.h>
#include <primitives/block.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/chaintype.h>

void initialize_work_kind()
{
    SelectParams(ChainType::REGTEST);
}

FUZZ_TARGET(work_kind, .init = initialize_work_kind)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const std::optional<CBlockHeader> header{ConsumeDeserializable<CBlockHeader>(provider)};
    if (!header) return;

    (void)header->GetBlockIdentity();
    (void)header->GetHash();
    const auto tag{Consensus::DecodeWorkKindTag(header->GetCompleteVersion())};
    if (!tag) return;
    const Consensus::WorkKind* kind{Consensus::LookupWorkKind(*tag)};
    if (!kind) return;
    (void)kind->TailRule(*header);
    (void)kind->EnabledAt(header->m_height);
    // FP8 MMA is 256³ MACs; keep it off the generic fuzz path.
    if (*tag == Consensus::WorkKindTag::FP8_GYM) return;
    (void)kind->WorkDigest(*header);
    (void)kind->Check(*header, header->nBits, Params().GetConsensus());
}
