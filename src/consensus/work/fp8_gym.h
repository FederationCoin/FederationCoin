// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_WORK_FP8_GYM_H
#define BITCOIN_CONSENSUS_WORK_FP8_GYM_H

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

class CBlockHeader;
class uint256;

namespace Consensus {

/** Kind-2 wire spec: RTX 50-series dense QMMA, frozen at genesis.
 *  Instruction: mma.sync.aligned.m16n8k32.row.col.f32.e4m3.e4m3.f32
 *  as that generation lowers it. Pin card: RTX 5070 Ti. Gym dimension,
 *  tile order, and rounding do not change in a later release. Other
 *  chips mine this kind only if they emit these bits. Golden digests in
 *  fp8_gym_tests are the 5070 Ti dump. */
static constexpr int FP8_DIM{256};
static constexpr int FP8_TILE_M{16};
static constexpr int FP8_TILE_N{8};
static constexpr int FP8_TILE_K{32};
static constexpr int FP8_MT{16};
static constexpr int FP8_NT{32};
static constexpr int FP8_KT{8};
static constexpr int FP8_MATRIX_BYTES{FP8_DIM * FP8_DIM};
/** FDA fraction bits for one k=32 QMMA lane (RTX Blackwell QMMA). */
static constexpr int FP8_FDA_FRAC{25};

/** Decode one E4M3FN byte to binary32. Nullopt on NaN (0x7F/0xFF only).
 *  Max finite is 0x7E/0xFE = 448 (e=15, m=6). e=15, m=0..6 are finite. */
std::optional<float> DecodeE4M3FN(uint8_t b);
/** Pack one binary32 as RTX 50-series cvt.rn.satfinite to E4M3FN.
 *  Inf saturates to ±448. NaN encodes 0x7F/0xFF. A zero result keeps
 *  the sign (0x00 or 0x80), matching the pin card. Ties round to even
 *  mantissa. */
uint8_t QuantizeE4M3FN(float x);

/** Expand A then B (65536 each) from the 164-byte header. Remaps 0x7F/0xFF
 *  to max finite 0x7E/0xFE. Seed is Blake2b of domain || header. */
void Fp8ExpandAB(const CBlockHeader& header, std::vector<uint8_t>& a, std::vector<uint8_t>& b);

/**
 * One dense QMMA k=32 lane: D = A[32]·B[32] + C in the fused 25-fraction-bit
 * accumulate, then RZ-normalize to binary32. a_k and b_k length 32.
 * False if an A/B NaN encoding survived remap.
 */
bool Fp8QmmaK32(std::span<const uint8_t> a_k, std::span<const uint8_t> b_k, float c, float& out);

/**
 * Tiled MMA. C is row-major FP8_DIM*FP8_DIM binary32.
 * Each output cell is eight chained k=32 QMMA lanes (kt 0..7).
 * Tile loops (kt, mt, nt) are the instruction order.
 * False if A/B has a NaN encoding that survived remap.
 */
bool Fp8TiledMma(std::span<const uint8_t> a, std::span<const uint8_t> b, std::vector<float>& c);

/** Quantize C to packed E4M3FN. Nullopt if length is not the matrix. */
std::optional<std::vector<uint8_t>> Fp8QuantizeC(std::span<const float> c);

/** Packed-C digest, or nullopt if MMA fails. Not uint256::ONE. */
std::optional<uint256> Fp8GymDigest(const CBlockHeader& header);
uint256 Fp8PackedCDigest(std::span<const uint8_t> packed_c);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_WORK_FP8_GYM_H
