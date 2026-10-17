// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// RTX 50-series tensor-core gym. Not ctest. sm_120.

#include <cstdint>
#include <cstdio>
#include <cuda_runtime.h>

namespace {

constexpr int kDim = 256;
constexpr int kTileM = 16;
constexpr int kTileN = 8;
constexpr int kTileK = 32;
constexpr int kMt = 16;
constexpr int kNt = 32;
constexpr int kKt = 8;

__device__ void PackA(uint32_t a_reg[4], const uint8_t* A, int mt, int kt, int lane)
{
    const int groupID = lane >> 2;
    const int threadID_in_group = lane % 4;
    for (int i = 0; i < 16; ++i) {
        const int row = (i < 4 || (i >= 8 && i < 12)) ? groupID : groupID + 8;
        const int col = (threadID_in_group * 4) + (i & 3) + (i >= 8 ? 16 : 0);
        const uint8_t v = A[(mt * kTileM + row) * kDim + (kt * kTileK + col)];
        const int r = i / 4;
        const int s = i % 4;
        if (s == 0) a_reg[r] = 0;
        a_reg[r] |= static_cast<uint32_t>(v) << (8 * s);
    }
}

__device__ void PackB(uint32_t b_reg[2], const uint8_t* B, int nt, int kt, int lane)
{
    const int groupID = lane >> 2;
    const int threadID_in_group = lane % 4;
    for (int i = 0; i < 8; ++i) {
        const int row = (threadID_in_group * 4) + (i & 3) + (i >= 4 ? 16 : 0);
        const int col = groupID;
        const uint8_t v = B[(kt * kTileK + row) * kDim + (nt * kTileN + col)];
        const int r = i / 4;
        const int s = i % 4;
        if (s == 0) b_reg[r] = 0;
        b_reg[r] |= static_cast<uint32_t>(v) << (8 * s);
    }
}

__device__ void Mma16832(float acc[4], const uint32_t a[4], const uint32_t b[2])
{
    asm volatile(
        "mma.sync.aligned.m16n8k32.row.col.f32.e4m3.e4m3.f32 "
        "{%0,%1,%2,%3}, {%4,%5,%6,%7}, {%8,%9}, {%0,%1,%2,%3};\n"
        : "+f"(acc[0]), "+f"(acc[1]), "+f"(acc[2]), "+f"(acc[3])
        : "r"(a[0]), "r"(a[1]), "r"(a[2]), "r"(a[3]),
          "r"(b[0]), "r"(b[1]));
}

__global__ void GymMmaKernel(const uint8_t* A, const uint8_t* B, float* C)
{
    const int tile = blockIdx.x;
    const int mt = tile / kNt;
    const int nt = tile % kNt;
    const int lane = threadIdx.x;
    if (mt >= kMt || lane >= 32) return;

    const int groupID = lane >> 2;
    const int threadID_in_group = lane % 4;
    float acc[4] = {0.f, 0.f, 0.f, 0.f};
    for (int ci = 0; ci < 4; ++ci) {
        const int row = (ci < 2) ? groupID : groupID + 8;
        const int col = (threadID_in_group * 2) + (ci & 1);
        acc[ci] = C[(mt * kTileM + row) * kDim + (nt * kTileN + col)];
    }
    for (int kt = 0; kt < kKt; ++kt) {
        uint32_t a_reg[4], b_reg[2];
        PackA(a_reg, A, mt, kt, lane);
        PackB(b_reg, B, nt, kt, lane);
        Mma16832(acc, a_reg, b_reg);
    }
    for (int ci = 0; ci < 4; ++ci) {
        const int row = (ci < 2) ? groupID : groupID + 8;
        const int col = (threadID_in_group * 2) + (ci & 1);
        C[(mt * kTileM + row) * kDim + (nt * kTileN + col)] = acc[ci];
    }
}

__device__ uint8_t CvtSatfiniteE4M3(float x)
{
    unsigned short pair;
    // Both f32 sources are x so either packed byte is the satfinite E4M3FN code.
    asm volatile("cvt.rn.satfinite.e4m3x2.f32 %0, %1, %1;" : "=h"(pair) : "f"(x));
    return static_cast<uint8_t>(pair & 0xFFu);
}

__global__ void PackKernel(const float* C, uint8_t* packed, int n)
{
    const int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    packed[i] = CvtSatfiniteE4M3(C[i]);
}

int EnsureSm120()
{
    static int selected{-2};
    if (selected >= 0) return 0;
    if (selected == -1) return 1;
    int n{0};
    if (cudaGetDeviceCount(&n) != cudaSuccess) {
        selected = -1;
        return 1;
    }
    for (int i{0}; i < n; ++i) {
        cudaDeviceProp p{};
        if (cudaGetDeviceProperties(&p, i) != cudaSuccess) continue;
        if (p.major != 12) continue;
        if (cudaSetDevice(i) != cudaSuccess) continue;
        std::fprintf(stderr, "fp8_blackwell_kat using %s sm_%d%d\n", p.name, p.major, p.minor);
        selected = i;
        return 0;
    }
    std::fprintf(stderr, "fp8_blackwell_kat: no sm_12x device\n");
    selected = -1;
    return 1;
}

int SyncKernel(const char* what)
{
    const cudaError_t launch{cudaGetLastError()};
    if (launch != cudaSuccess) {
        std::fprintf(stderr, "%s launch: %s\n", what, cudaGetErrorString(launch));
        return 2;
    }
    const cudaError_t err{cudaDeviceSynchronize()};
    if (err != cudaSuccess) {
        std::fprintf(stderr, "%s sync: %s\n", what, cudaGetErrorString(err));
        return 2;
    }
    return 0;
}

} // namespace

extern "C" int fp8_blackwell_mma(const uint8_t* a_host, const uint8_t* b_host, float* c_host)
{
    if (EnsureSm120() != 0) return 1;
    uint8_t *a_dev{nullptr}, *b_dev{nullptr};
    float* c_dev{nullptr};
    const size_t mat = static_cast<size_t>(kDim) * kDim;
    if (cudaMalloc(&a_dev, mat) != cudaSuccess) return 1;
    if (cudaMalloc(&b_dev, mat) != cudaSuccess) return 1;
    if (cudaMalloc(&c_dev, mat * sizeof(float)) != cudaSuccess) return 1;
    cudaMemcpy(a_dev, a_host, mat, cudaMemcpyHostToDevice);
    cudaMemcpy(b_dev, b_host, mat, cudaMemcpyHostToDevice);
    cudaMemset(c_dev, 0, mat * sizeof(float));
    GymMmaKernel<<<kMt * kNt, 32>>>(a_dev, b_dev, c_dev);
    const int rc{SyncKernel("mma")};
    if (rc == 0) {
        cudaMemcpy(c_host, c_dev, mat * sizeof(float), cudaMemcpyDeviceToHost);
    }
    cudaFree(a_dev);
    cudaFree(b_dev);
    cudaFree(c_dev);
    return rc;
}

extern "C" int fp8_blackwell_pack(const float* c_host, uint8_t* packed_host, int n)
{
    if (EnsureSm120() != 0) return 1;
    float* c_dev{nullptr};
    uint8_t* p_dev{nullptr};
    if (cudaMalloc(&c_dev, static_cast<size_t>(n) * sizeof(float)) != cudaSuccess) return 1;
    if (cudaMalloc(&p_dev, static_cast<size_t>(n)) != cudaSuccess) return 1;
    cudaMemcpy(c_dev, c_host, static_cast<size_t>(n) * sizeof(float), cudaMemcpyHostToDevice);
    PackKernel<<<(n + 255) / 256, 256>>>(c_dev, p_dev, n);
    const int rc{SyncKernel("pack")};
    if (rc == 0) {
        cudaMemcpy(packed_host, p_dev, static_cast<size_t>(n), cudaMemcpyDeviceToHost);
    }
    cudaFree(c_dev);
    cudaFree(p_dev);
    return rc;
}
