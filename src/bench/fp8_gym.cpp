// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/work/fp8_gym.h>
#include <consensus/work/kind.h>
#include <primitives/block.h>

static CBlockHeader Fp8Header()
{
    CBlockHeader header;
    header.m_header_v2 = true;
    header.nVersion = 4;
    Consensus::ApplyWorkKindTag(header, Consensus::WorkKindTag::FP8_GYM);
    header.nTime = 1;
    header.nBits = 0x207fffff;
    header.nNonce = 1;
    return header;
}

static void Fp8GymVerify(benchmark::Bench& bench)
{
    const CBlockHeader header{Fp8Header()};
    bench.unit("header").run([&] {
        (void)Consensus::Fp8GymDigest(header);
    });
}

BENCHMARK(Fp8GymVerify, benchmark::PriorityLevel::HIGH);
