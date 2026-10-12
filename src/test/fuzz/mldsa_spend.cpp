// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa44_spend.h>
#include <consensus/mldsa87_spend.h>
#include <span.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <vector>

FUZZ_TARGET(mldsa_spend)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const std::size_t n{provider.ConsumeIntegralInRange<std::size_t>(0, 16)};
    std::vector<std::vector<unsigned char>> witness;
    witness.reserve(n);
    for (std::size_t i{0}; i < n; ++i) {
        witness.push_back(ConsumeRandomLengthByteVector(provider, 5000));
    }

    std::array<unsigned char, 32> program_raw{};
    const auto prog{provider.ConsumeBytes<unsigned char>(32)};
    std::copy_n(prog.begin(), std::min(prog.size(), program_raw.size()), program_raw.begin());
    const uint256 program{Span<const unsigned char>{program_raw.data(), program_raw.size()}};

    std::array<unsigned char, 32> sighash{};
    const auto sh{provider.ConsumeBytes<unsigned char>(32)};
    std::copy_n(sh.begin(), std::min(sh.size(), sighash.size()), sighash.begin());

    (void)Consensus::ClassifyMlDsa44Witness(witness);
    (void)Consensus::ClassifyMlDsa87Witness(witness);
    (void)Consensus::CheckSingleKey44Spend(program, witness, sighash);
    (void)Consensus::CheckMultisig44Spend(program, witness, sighash);
    (void)Consensus::CheckSingleKey87Spend(program, witness, sighash);
    (void)Consensus::CheckMultisig87Spend(program, witness, sighash);
    (void)Consensus::MergeMlDsa44Witnesses({witness}, sighash);
    (void)Consensus::MergeMlDsa87Witnesses({witness}, sighash);
}
