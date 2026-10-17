// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <flatfile.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <cassert>
#include <cstdint>
#include <memory>
#include <vector>

static CBlock BenchBlock(const TestingSetup& setup)
{
    return setup.m_node.chainman->GetParams().GenesisBlock();
}

static void SaveBlockBench(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const TestingSetup>(ChainType::MAIN)};
    auto& blockman{testing_setup->m_node.chainman->m_blockman};
    const CBlock block{BenchBlock(*testing_setup)};
    bench.run([&] {
        const auto pos{blockman.WriteBlock(block, 0)};
        assert(!pos.IsNull());
    });
}

static void ReadBlockBench(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const TestingSetup>(ChainType::MAIN)};
    auto& blockman{testing_setup->m_node.chainman->m_blockman};
    const auto pos{blockman.WriteBlock(BenchBlock(*testing_setup), 0)};
    CBlock block;
    bench.run([&] {
        const auto success{blockman.ReadBlock(block, pos)};
        assert(success);
    });
}

static void ReadRawBlockBench(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const TestingSetup>(ChainType::MAIN)};
    auto& blockman{testing_setup->m_node.chainman->m_blockman};
    const auto pos{blockman.WriteBlock(BenchBlock(*testing_setup), 0)};
    std::vector<uint8_t> block_data;
    blockman.ReadRawBlock(block_data, pos); // warmup
    bench.run([&] {
        const auto success{blockman.ReadRawBlock(block_data, pos)};
        assert(success);
    });
}

BENCHMARK(SaveBlockBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(ReadBlockBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(ReadRawBlockBench, benchmark::PriorityLevel::HIGH);
