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
 *  fp8_gym_tests are the 5070 Ti dump.
 *
 *  Pipeline (see fp8_gym.md): v2 header -> Blake2b seed
 *  (domain gfcn-fp8-gym-v2) -> 2048 x 64-byte expands -> A then B
 *  256x256 E4M3FN with NaN encodings remapped to max finite -> tiled
 *  QMMA (k_tile, m_tile, n_tile) -> C binary32 -> cvt.rn.satfinite to
 *  packed E4M3FN -> Blake2b (domain gfcn-fp8-gym-out-v2). */
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
 *  Signed zero decodes as +0.0f (the pin card). Max finite is 0x7E/0xFE
 *  = 448 (stored exponent 15, mantissa 6). Stored exponent 15 with
 *  mantissa 0..6 is finite. Why: miners and the node must agree on every
 *  expanded A/B byte before QMMA. */
std::optional<float> DecodeE4M3FN(uint8_t encoded);

/** Pack one binary32 as RTX 50-series cvt.rn.satfinite to E4M3FN.
 *  Inf uses the IEEE satfinite encoding ±448 (0x7E/0xFE), not a
 *  leftover-hole Saturated() block. NaN encodes 0x7F/0xFF with sign.
 *  A zero result keeps the sign (0x00 or 0x80). Ties round to even
 *  mantissa. Why: output C must match the pin card before the digest. */
uint8_t QuantizeE4M3FN(float value);

/** Expand A then B (65536 bytes each) from the v2 header. Remaps
 *  0x7F/0xFF to max finite 0x7E/0xFE so QMMA never sees a NaN encoding.
 *  Seed is Blake2b-256 of ASCII domain "gfcn-fp8-gym-v2" || header.
 *  Why: the matrices are a function of the header alone. */
void Fp8ExpandAB(const CBlockHeader& header, std::vector<uint8_t>& matrix_a, std::vector<uint8_t>& matrix_b);

/** One dense QMMA k=32 lane: D = A[32]·B[32] + accumulator in the fused
 *  25-fraction-bit accumulate, then RZ-normalize to binary32.
 *  a_lane_k32 and b_lane_k32 length 32. False if an A/B NaN encoding
 *  survived remap. Why: this is the instruction the pin card lowers. */
bool Fp8QmmaK32(std::span<const uint8_t> a_lane_k32, std::span<const uint8_t> b_lane_k32,
                float accumulator, float& out);

/** Tiled MMA. matrix_c is row-major FP8_DIM*FP8_DIM binary32.
 *  Each output cell is eight chained k=32 QMMA lanes (k_tile 0..7).
 *  Tile loops (k_tile, m_tile, n_tile) are the instruction order.
 *  False if A/B has a NaN encoding that survived remap.
 *  Why: order is consensus; a different nest would be a different digest. */
bool Fp8TiledMma(std::span<const uint8_t> matrix_a, std::span<const uint8_t> matrix_b, std::vector<float>& matrix_c);

/** Quantize each C cell to packed E4M3FN. Nullopt if length is not the matrix. */
std::optional<std::vector<uint8_t>> Fp8QuantizeC(std::span<const float> matrix_c);

/** Packed-C digest, or nullopt if MMA fails. Not uint256::ONE.
 *  Blake2b-256 of ASCII domain "gfcn-fp8-gym-out-v2" || packed C. */
std::optional<uint256> Fp8GymDigest(const CBlockHeader& header);
uint256 Fp8PackedCDigest(std::span<const uint8_t> packed_c);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_WORK_FP8_GYM_H
