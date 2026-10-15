// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_WORK_FP8_GYM_H
#define BITCOIN_CONSENSUS_WORK_FP8_GYM_H

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

class CBlockHeader;
class uint256;

namespace Consensus {

/** Kind-2 wire spec. This tiled E4M3FN binary32 MMA is the digest. Gym
 *  dimension, tile order, and rounding do not change in a later release.
 *  A SIMD port that changes rounding is a consensus change. Compile with
 *  FMA contraction off (see fp8_gym.cpp). Golden digest in fp8_gym_tests. */
static constexpr int FP8_DIM{256};
static constexpr int FP8_TILE_M{16};
static constexpr int FP8_TILE_N{8};
static constexpr int FP8_TILE_K{32};
static constexpr int FP8_MT{16};
static constexpr int FP8_NT{32};
static constexpr int FP8_KT{8};
static constexpr int FP8_MATRIX_BYTES{FP8_DIM * FP8_DIM};

/** Decode one E4M3FN byte to binary32. Nullopt on NaN (e==15, m==7). */
std::optional<float> DecodeE4M3FN(uint8_t b);
/** Quantize binary32 to E4M3FN. Nullopt on Inf/NaN. Nearest finite code;
 *  ties to even mantissa, then lower code. Clamp mag > 448 to 0x7E/0xFE. */
std::optional<uint8_t> QuantizeE4M3FN(float x);

/** Expand A then B (65536 each) from the 164-byte header. Remaps 0x7F/0xFF
 *  to max finite 0x7E/0xFE. Seed is Blake2b of domain || header. */
void Fp8ExpandAB(const CBlockHeader& header, std::vector<uint8_t>& a, std::vector<uint8_t>& b);

/**
 * Tiled MMA. C is row-major FP8_DIM*FP8_DIM binary32.
 * Each cell: acc = acc + prod in binary32, no fused multiply-add.
 * Tile loops (kt, mt, nt, i, j, kk) are the accumulation order.
 * False if any mul/add produces Inf or NaN, or a/b has a NaN encoding
 * that survived remap (should not).
 */
bool Fp8TiledMma(std::span<const uint8_t> a, std::span<const uint8_t> b, std::vector<float>& c);

/** Quantize C to packed E4M3FN. Nullopt if any Inf/NaN. */
std::optional<std::vector<uint8_t>> Fp8QuantizeC(std::span<const float> c);

/** Packed-C digest, or nullopt if MMA/quantize fails. Not uint256::ONE. */
std::optional<uint256> Fp8GymDigest(const CBlockHeader& header);
uint256 Fp8PackedCDigest(std::span<const uint8_t> packed_c);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_WORK_FP8_GYM_H
