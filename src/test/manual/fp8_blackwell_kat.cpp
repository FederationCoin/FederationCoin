// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Manual RTX 50-series gym KAT. Not registered with ctest.
// Needs nvcc that supports sm_120 (CUDA 12.8+), not distro 11.5:
//   cmake -DENABLE_FP8_BLACKWELL_KAT=ON -DCMAKE_CUDA_COMPILER=/usr/local/cuda-13.2/bin/nvcc
//   ./build/bin/fp8_blackwell_kat dump
//   ./build/bin/fp8_blackwell_kat grind 10000

#include <consensus/work/fp8_gym.h>
#include <consensus/work/kind.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/translation.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

extern "C" int fp8_blackwell_mma(const uint8_t* a_host, const uint8_t* b_host, float* c_host);
extern "C" int fp8_blackwell_pack(const float* c_host, uint8_t* packed_host, int n);

static CBlockHeader FrozenHeader()
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

static int DumpOne(const char* name, const std::vector<uint8_t>& a, const std::vector<uint8_t>& b)
{
    std::vector<float> c_gpu(Consensus::FP8_MATRIX_BYTES, 0.0f);
    if (fp8_blackwell_mma(a.data(), b.data(), c_gpu.data()) != 0) {
        std::fprintf(stderr, "%s: mma failed\n", name);
        return 1;
    }
    std::vector<uint8_t> packed_gpu(Consensus::FP8_MATRIX_BYTES);
    if (fp8_blackwell_pack(c_gpu.data(), packed_gpu.data(), Consensus::FP8_MATRIX_BYTES) != 0) {
        std::fprintf(stderr, "%s: pack failed\n", name);
        return 1;
    }
    std::vector<float> c_cpu;
    if (!Consensus::Fp8TiledMma(a, b, c_cpu)) {
        std::fprintf(stderr, "%s: cpu mma failed\n", name);
        return 1;
    }
    const auto packed_cpu{Consensus::Fp8QuantizeC(c_cpu)};
    if (!packed_cpu) {
        std::fprintf(stderr, "%s: cpu pack failed\n", name);
        return 1;
    }
    const uint256 d_gpu{Consensus::Fp8PackedCDigest(packed_gpu)};
    const uint256 d_cpu{Consensus::Fp8PackedCDigest(*packed_cpu)};
    std::printf("%s c0 gpu %.9g cpu %.9g\n", name, static_cast<double>(c_gpu[0]), static_cast<double>(c_cpu[0]));
    std::printf("%s gpu %s\n", name, d_gpu.ToString().c_str());
    std::printf("%s cpu %s\n", name, d_cpu.ToString().c_str());
    if (d_gpu != d_cpu) {
        std::fprintf(stderr, "%s: gpu/cpu digest mismatch\n", name);
        return 2;
    }
    int packed_mismatch{0};
    for (int i{0}; i < Consensus::FP8_MATRIX_BYTES; ++i) {
        if (packed_gpu[i] != (*packed_cpu)[i]) ++packed_mismatch;
    }
    std::printf("%s packed_mismatch %d\n", name, packed_mismatch);
    return packed_mismatch == 0 ? 0 : 2;
}

static int Dump()
{
    std::vector<uint8_t> zeros(Consensus::FP8_MATRIX_BYTES, 0);
    std::vector<uint8_t> maxf(Consensus::FP8_MATRIX_BYTES, 0x7E);
    int rc{0};
    rc |= DumpOne("all_zero", zeros, zeros);
    rc |= DumpOne("all_max", maxf, maxf);
    CBlockHeader header{FrozenHeader()};
    std::vector<uint8_t> a, b;
    Consensus::Fp8ExpandAB(header, a, b);
    rc |= DumpOne("frozen_header", a, b);
    const auto digest{Consensus::Fp8GymDigest(header)};
    if (!digest) {
        std::fprintf(stderr, "frozen_header: Fp8GymDigest failed\n");
        return 1;
    }
    std::printf("frozen_header Fp8GymDigest %s\n", digest->ToString().c_str());
    return rc;
}

static int Grind(int count, int start)
{
    CBlockHeader header{FrozenHeader()};
    int mismatch{0};
    const int end{start + count};
    for (int n{start}; n < end; ++n) {
        header.nNonce = static_cast<uint32_t>(n);
        std::vector<uint8_t> a, b;
        Consensus::Fp8ExpandAB(header, a, b);
        std::vector<float> c_gpu(Consensus::FP8_MATRIX_BYTES, 0.0f);
        if (fp8_blackwell_mma(a.data(), b.data(), c_gpu.data()) != 0) return 1;
        std::vector<uint8_t> packed_gpu(Consensus::FP8_MATRIX_BYTES);
        if (fp8_blackwell_pack(c_gpu.data(), packed_gpu.data(), Consensus::FP8_MATRIX_BYTES) != 0) return 1;
        std::vector<float> c_cpu;
        if (!Consensus::Fp8TiledMma(a, b, c_cpu)) {
            std::fprintf(stderr, "grind nonce %d cpu mma failed\n", n);
            return 1;
        }
        const auto packed_cpu{Consensus::Fp8QuantizeC(c_cpu)};
        if (!packed_cpu) return 1;
        const uint256 d_gpu{Consensus::Fp8PackedCDigest(packed_gpu)};
        const uint256 d_cpu{Consensus::Fp8PackedCDigest(*packed_cpu)};
        if (d_gpu != d_cpu) {
            int packed_mismatch{0};
            int first{-1};
            for (int i{0}; i < Consensus::FP8_MATRIX_BYTES; ++i) {
                if (packed_gpu[i] != (*packed_cpu)[i]) {
                    if (first < 0) first = i;
                    ++packed_mismatch;
                }
            }
            std::fprintf(stderr,
                         "grind nonce %d mismatch packed_mismatch %d first %d gpu_c %a cpu_c %a gpu_p 0x%02x cpu_p 0x%02x\n",
                         n, packed_mismatch, first,
                         first >= 0 ? static_cast<double>(c_gpu[first]) : 0.0,
                         first >= 0 ? static_cast<double>(c_cpu[first]) : 0.0,
                         first >= 0 ? packed_gpu[first] : 0,
                         first >= 0 ? (*packed_cpu)[first] : 0);
            ++mismatch;
            if (mismatch >= 8) break;
        }
        if ((n - start + 1) % 100 == 0) {
            std::printf("grind %d ok_mismatch %d\n", n + 1, mismatch);
            std::fflush(stdout);
        }
    }
    std::printf("grind done start=%d count=%d mismatch=%d\n", start, count, mismatch);
    return mismatch == 0 ? 0 : 2;
}

int main(int argc, char** argv)
{
    const char* mode{argc > 1 ? argv[1] : "dump"};
    if (std::strcmp(mode, "dump") == 0) return Dump();
    if (std::strcmp(mode, "grind") == 0) {
        const int count{argc > 2 ? std::atoi(argv[2]) : 10000};
        const int start{argc > 3 ? std::atoi(argv[3]) : 0};
        return Grind(count, start);
    }
    std::fprintf(stderr, "usage: fp8_blackwell_kat dump|grind [count] [start_nonce]\n");
    return 1;
}
