// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_WORK_COST_H
#define BITCOIN_CONSENSUS_WORK_COST_H

#include <cstdint>
#include <limits>

namespace Consensus {

/** Try-cost unit and named conversions for T0[k] = T0_ref * O_k * D_k.
 *
 *  The unit (B2BC) is one Blake2b compression (128-byte block, 12 rounds).
 *  Kind-0 ASIC grind is one compression of the ~80-byte Sv1 payload.
 *
 *  Hash-cost offset O_k is specified native-hash ops vs that reference, not
 *  digest width. All four Checks compare a 256-bit digest to compact T. A
 *  512-bit squeeze is not twice as hard at the same T.
 *
 *  Knob discount D_k is extra pre-hash work (the gym). D = 1 except FP8.
 *  Gym op counts (2048, 513, 256^3) are the product gym. kFp8MacsPerB2bc is
 *  the product conversion that anchors that gym to compute cost.
 *
 *  Shared S is unchanged. Changing a conversion integer is a fork. */

/** SHA-256d of 80 bytes: 2 inner blocks + 1 outer. Exact (remainder 0) vs
 *  kSha256CompressionsPerB2bc. */
static constexpr uint64_t kSha256dCompressions{3};
/** 3 SHA-256 compressions = 1 B2BC (32-bit vs 64-bit ARX sketch). */
static constexpr uint64_t kSha256CompressionsPerB2bc{3};

/** Poseidon2 preimage is Blake2b-256 of domain || 166-byte header (2 compressions). */
static constexpr uint64_t kPoseidon2PreimageB2bc{2};
/** 96-byte sponge: 4 absorbs/pad + second squeeze. */
static constexpr uint64_t kPoseidon2Permutes{5};
/** 1 Goldilocks permute ≈ 6 B2BC (x^7 vs Blake2b G). */
static constexpr uint64_t kB2bcPerPoseidon2Permute{6};

/** FP8 seed Blake2b-256 of 16 + 166 bytes. */
static constexpr uint64_t kFp8SeedB2bc{2};
/** 2048 × Blake2b-64 of 40-byte (seed || le64). */
static constexpr uint64_t kFp8ExpandCount{2048};
/** Blake2b-256 of 19 + 65536 packed-C bytes: ceil(65555/128). */
static constexpr uint64_t kFp8OutB2bc{513};
/** Tiled QMMA: 256×256×256 E4M3 MACs. */
static constexpr uint64_t kFp8Macs{256ull * 256ull * 256ull};
/** Product conversion that anchors the gym: 1 B2BC ≈ 768 64-bit adds ≈ 49152
 *  bit-ops; 1 E4M3 MAC ≈ 224. Retuning this ratio is a fork. */
static constexpr uint64_t kFp8MacsPerB2bc{219};
static constexpr uint64_t kFp8Quantizes{65536};
/** One QuantizeE4M3FN ≈ one add-equivalent vs 768 adds/B2BC. Floor toward zero. */
static constexpr uint64_t kFp8QuantizesPerB2bc{768};

/** SHA-256d hash-cost offset in B2BC. Exact: 3/3. */
inline constexpr uint64_t Sha256dHashCostB2bc()
{
    static_assert(kSha256dCompressions % kSha256CompressionsPerB2bc == 0);
    return kSha256dCompressions / kSha256CompressionsPerB2bc;
}

/** Poseidon2 hash-cost offset in B2BC. */
inline constexpr uint64_t Poseidon2HashCostB2bc()
{
    static_assert(kPoseidon2Permutes <= std::numeric_limits<uint64_t>::max() / kB2bcPerPoseidon2Permute);
    static_assert(kPoseidon2PreimageB2bc <= std::numeric_limits<uint64_t>::max() - kPoseidon2Permutes * kB2bcPerPoseidon2Permute);
    return kPoseidon2PreimageB2bc + kPoseidon2Permutes * kB2bcPerPoseidon2Permute;
}

/** FP8 knob discount in B2BC. MAC and quantize divides floor toward zero. */
inline constexpr uint64_t Fp8KnobDiscountB2bc()
{
    static_assert(kFp8MacsPerB2bc > 0);
    static_assert(kFp8QuantizesPerB2bc > 0);
    constexpr uint64_t macs_b2bc{kFp8Macs / kFp8MacsPerB2bc};
    constexpr uint64_t quant_b2bc{kFp8Quantizes / kFp8QuantizesPerB2bc};
    static_assert(kFp8SeedB2bc <= std::numeric_limits<uint64_t>::max() - kFp8ExpandCount);
    constexpr uint64_t seed_expand{kFp8SeedB2bc + kFp8ExpandCount};
    static_assert(seed_expand <= std::numeric_limits<uint64_t>::max() - macs_b2bc);
    constexpr uint64_t with_macs{seed_expand + macs_b2bc};
    static_assert(with_macs <= std::numeric_limits<uint64_t>::max() - quant_b2bc);
    constexpr uint64_t with_quant{with_macs + quant_b2bc};
    static_assert(with_quant <= std::numeric_limits<uint64_t>::max() - kFp8OutB2bc);
    return with_quant + kFp8OutB2bc;
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_WORK_COST_H
