// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/work/fp8_gym.h>

#include <crypto/blake2b.h>
#include <crypto/common.h>
#include <hash.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>
#include <util/check.h>

#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <variant>

namespace Consensus {
namespace {

template <class... Arms>
struct VisitArms : Arms... {
    using Arms::operator()...;
};
template <class... Arms>
VisitArms(Arms...) -> VisitArms<Arms...>;

struct E4M3NaN {};
struct E4M3SignedZero {
    bool negative{false};
};
struct E4M3FiniteNonZero {
    bool negative{false};
    uint32_t three_bit_magnitude{0};
    int32_t unbiased_exponent{0};
};
using E4M3Encoding = std::variant<E4M3NaN, E4M3SignedZero, E4M3FiniteNonZero>;

E4M3Encoding ClassifyE4M3FN(uint8_t encoded)
{
    const unsigned sign_bit{static_cast<unsigned>((encoded >> 7) & 1)};
    const unsigned stored_exponent{static_cast<unsigned>((encoded >> 3) & 15)};
    const unsigned stored_mantissa{static_cast<unsigned>(encoded & 7)};
    const bool negative{sign_bit != 0};
    if (stored_exponent == 15 && stored_mantissa == 7) return E4M3NaN{};
    if (stored_exponent == 0 && stored_mantissa == 0) return E4M3SignedZero{negative};
    if (stored_exponent == 0) {
        return E4M3FiniteNonZero{negative, stored_mantissa, -6};
    }
    return E4M3FiniteNonZero{negative, 8 + stored_mantissa, static_cast<int32_t>(stored_exponent) - 7};
}

float SignedLdexp(uint32_t three_bit_magnitude, int32_t power_of_two, bool negative)
{
    // E4M3 finite non-zero: magnitude 1..15, unbiased exp -6..7. Exact in
    // binary32 without libm. Do not retune QuantizeE4M3FN.
    Assume(three_bit_magnitude >= 1 && three_bit_magnitude <= 15);
    Assume(power_of_two >= -6 && power_of_two <= 7);
    float magnitude;
    if (power_of_two >= 0) {
        magnitude = static_cast<float>(three_bit_magnitude << power_of_two);
    } else {
        magnitude = static_cast<float>(three_bit_magnitude) /
                    static_cast<float>(1u << static_cast<uint32_t>(-power_of_two));
    }
    return negative ? -magnitude : magnitude;
}

struct IeeeFp32NaN {
    bool negative{false};
};
struct IeeeFp32Inf {
    bool negative{false};
};
struct IeeeFp32Zero {
    bool negative{false};
};
struct IeeeFp32Finite {
    bool negative{false};
    int32_t unbiased_exponent{0};
    uint64_t significand_fda{0};
};
using IeeeFp32Class = std::variant<IeeeFp32NaN, IeeeFp32Inf, IeeeFp32Zero, IeeeFp32Finite>;

IeeeFp32Class ClassifyIeeeFp32(float value)
{
    const uint32_t bits{std::bit_cast<uint32_t>(value)};
    const bool negative{(bits >> 31) != 0};
    const int stored_exponent{static_cast<int>((bits >> 23) & 255)};
    const uint32_t stored_mantissa{bits & 0x7fffffu};
    if (stored_exponent == 255 && stored_mantissa != 0) return IeeeFp32NaN{negative};
    if (stored_exponent == 255) return IeeeFp32Inf{negative};
    if (stored_exponent == 0 && stored_mantissa == 0) return IeeeFp32Zero{negative};
    if (stored_exponent == 0) {
        return IeeeFp32Finite{negative, -126, static_cast<uint64_t>(stored_mantissa) << (FP8_FDA_FRAC - 23)};
    }
    return IeeeFp32Finite{
        negative,
        stored_exponent - 127,
        (uint64_t{0x800000} + stored_mantissa) << (FP8_FDA_FRAC - 23),
    };
}

uint32_t SignBit(bool negative)
{
    return negative ? 0x80000000u : 0u;
}

float BitsToFp32(uint32_t bits)
{
    return std::bit_cast<float>(bits);
}

float OverflowToInfinity(bool negative)
{
    return BitsToFp32(SignBit(negative) | 0x7f800000u);
}

uint64_t ShiftMagnitudeLeftOrZero(uint64_t magnitude, int shift_left)
{
    if (shift_left >= 64 || (magnitude << shift_left) >> shift_left != magnitude) return 0;
    return magnitude << shift_left;
}

uint64_t ShiftMagnitudeRightOrZero(uint64_t magnitude, int shift_right)
{
    if (shift_right >= 64) return 0;
    return magnitude >> shift_right;
}

float UnderflowToSubnormal(uint64_t magnitude, int scale, bool negative)
{
    const int shift_left{scale + 149};
    uint64_t stored{0};
    if (shift_left >= 0) {
        stored = ShiftMagnitudeLeftOrZero(magnitude, shift_left);
    } else {
        stored = ShiftMagnitudeRightOrZero(magnitude, -shift_left);
    }
    if (stored >= (uint64_t{1} << 23)) stored = (uint64_t{1} << 23) - 1;
    return BitsToFp32(SignBit(negative) | static_cast<uint32_t>(stored));
}

float NormalRangeToFp32(uint64_t magnitude, int leading_one_index, int32_t unbiased_exponent, bool negative)
{
    uint32_t mantissa_24;
    if (leading_one_index >= 23) {
        mantissa_24 = static_cast<uint32_t>(magnitude >> (leading_one_index - 23));
    } else {
        mantissa_24 = static_cast<uint32_t>(magnitude << (23 - leading_one_index));
    }
    const uint32_t exponent_field{static_cast<uint32_t>(unbiased_exponent + 127)};
    return BitsToFp32(SignBit(negative) | (exponent_field << 23) | (mantissa_24 & 0x7fffffu));
}

/** value = signed_magnitude * 2^scale, RZ to binary32 (truncate at bit 23 of the
 *  normalized significand). Origin: QMMA FDA F=25; |signed_magnitude| is at most
 *  33 * (4 << 25). Asserts that bound. */
float NormalizeRzFp32(int64_t signed_magnitude, int scale)
{
    static constexpr int64_t kTermMax{int64_t{4} << FP8_FDA_FRAC};
    static constexpr int64_t kSumMax{33 * kTermMax};
    Assert(signed_magnitude >= -kSumMax && signed_magnitude <= kSumMax);
    if (signed_magnitude == 0) return 0.0f;
    const bool negative{signed_magnitude < 0};
    const uint64_t magnitude{static_cast<uint64_t>(negative ? -signed_magnitude : signed_magnitude)};
    const int leading_one_index{63 - static_cast<int>(std::countl_zero(magnitude))};
    const int32_t unbiased_exponent{scale + leading_one_index};
    if (unbiased_exponent >= 128) return OverflowToInfinity(negative);
    if (unbiased_exponent <= -127) return UnderflowToSubnormal(magnitude, scale, negative);
    return NormalRangeToFp32(magnitude, leading_one_index, unbiased_exponent, negative);
}

uint8_t SignedE4M3Zero(bool negative)
{
    return negative ? uint8_t{0x80} : uint8_t{0x00};
}

uint8_t SignedE4M3NaN(bool negative)
{
    return negative ? uint8_t{0xFF} : uint8_t{0x7F};
}

uint8_t SignedE4M3MaxFinite(bool negative)
{
    return negative ? uint8_t{0xFE} : uint8_t{0x7E};
}

bool PreferE4M3Candidate(float distance, uint8_t mantissa, int code,
                         float best_distance, uint8_t best_mantissa, uint8_t best_code)
{
    if (distance < best_distance) return true;
    if (distance != best_distance) return false;
    const bool this_even{(mantissa % 2) == 0};
    const bool best_odd{(best_mantissa % 2) != 0};
    if (this_even && best_odd) return true;
    return this_even && (best_mantissa % 2 == 0) && code < best_code;
}

uint8_t QuantizeFiniteMagnitude(float magnitude, bool negative)
{
    if (magnitude > 448.0f) return SignedE4M3MaxFinite(negative);
    uint8_t best_code{0};
    float best_distance{std::numeric_limits<float>::infinity()};
    uint8_t best_mantissa{0};
    for (int code{0}; code <= 0x7E; ++code) {
        const auto decoded{DecodeE4M3FN(static_cast<uint8_t>(code))};
        if (!decoded) continue;
        const float distance{std::fabs(magnitude - *decoded)};
        const uint8_t mantissa{static_cast<uint8_t>(code & 7)};
        if (!PreferE4M3Candidate(distance, mantissa, code, best_distance, best_mantissa, best_code)) {
            continue;
        }
        best_distance = distance;
        best_code = static_cast<uint8_t>(code);
        best_mantissa = mantissa;
    }
    if (best_code == 0) return SignedE4M3Zero(negative);
    return negative ? static_cast<uint8_t>(best_code | 0x80) : best_code;
}

struct ProductTerm {
    bool zero{true};
    bool negative{false};
    int32_t unbiased_exponent{0};
    uint64_t significand_fda{0};
};

ProductTerm ProductFromMagnitudes(bool negative, uint32_t mag_a, int32_t exp_a, uint32_t mag_b, int32_t exp_b)
{
    Assert(mag_a <= 15 && mag_b <= 15);
    const uint32_t mag6{mag_a * mag_b};
    Assert(mag6 <= 225);
    ProductTerm term;
    term.zero = false;
    term.negative = negative;
    term.unbiased_exponent = exp_a + exp_b;
    term.significand_fda = static_cast<uint64_t>(mag6) << (FP8_FDA_FRAC - 6);
    return term;
}

bool FillProductTerm(uint8_t encoded_a, uint8_t encoded_b, ProductTerm& term)
{
    return std::visit(
        VisitArms{
            [](E4M3NaN, E4M3NaN) { return false; },
            [](E4M3NaN, E4M3SignedZero) { return false; },
            [](E4M3NaN, const E4M3FiniteNonZero&) { return false; },
            [](E4M3SignedZero, E4M3NaN) { return false; },
            [](const E4M3FiniteNonZero&, E4M3NaN) { return false; },
            [](E4M3SignedZero, E4M3SignedZero) { return true; },
            [](E4M3SignedZero, const E4M3FiniteNonZero&) { return true; },
            [](const E4M3FiniteNonZero&, E4M3SignedZero) { return true; },
            [&](const E4M3FiniteNonZero& finite_a, const E4M3FiniteNonZero& finite_b) {
                term = ProductFromMagnitudes(finite_a.negative != finite_b.negative,
                                             finite_a.three_bit_magnitude, finite_a.unbiased_exponent,
                                             finite_b.three_bit_magnitude, finite_b.unbiased_exponent);
                return true;
            },
        },
        ClassifyE4M3FN(encoded_a), ClassifyE4M3FN(encoded_b));
}

} // namespace

std::optional<float> DecodeE4M3FN(uint8_t encoded)
{
    return std::visit(VisitArms{
                          [](E4M3NaN) -> std::optional<float> { return std::nullopt; },
                          [](E4M3SignedZero) -> std::optional<float> { return 0.0f; },
                          [](const E4M3FiniteNonZero& finite) -> std::optional<float> {
                              return SignedLdexp(finite.three_bit_magnitude, finite.unbiased_exponent - 3,
                                                 finite.negative);
                          },
                      },
                      ClassifyE4M3FN(encoded));
}

uint8_t QuantizeE4M3FN(float value)
{
    return std::visit(VisitArms{
                          [](const IeeeFp32NaN& nan) { return SignedE4M3NaN(nan.negative); },
                          [](const IeeeFp32Inf& inf) { return SignedE4M3MaxFinite(inf.negative); },
                          [](const IeeeFp32Zero& zero) { return SignedE4M3Zero(zero.negative); },
                          [value](const IeeeFp32Finite& finite) {
                              const float magnitude{std::fabs(value)};
                              return QuantizeFiniteMagnitude(magnitude, finite.negative);
                          },
                      },
                      ClassifyIeeeFp32(value));
}

void Fp8ExpandAB(const CBlockHeader& header, std::vector<uint8_t>& matrix_a, std::vector<uint8_t>& matrix_b)
{
    DataStream stream;
    stream << header;
    static constexpr char kDomain[]{"gfcn-fp8-gym-v2"};
    std::array<unsigned char, 16 + BLOCK_HEADER_V2_SERIALIZED_SIZE> seed_msg{};
    std::memcpy(seed_msg.data(), kDomain, 16);
    Assert(stream.size() == BLOCK_HEADER_V2_SERIALIZED_SIZE);
    std::memcpy(seed_msg.data() + 16, stream.data(), BLOCK_HEADER_V2_SERIALIZED_SIZE);
    uint256 seed;
    Assert(0 == blake2b_nokey(seed.begin(), 32, seed_msg.data(), seed_msg.size()));

    std::vector<uint8_t> stream_bytes(2 * FP8_MATRIX_BYTES);
    unsigned char block[64];
    unsigned char expand_in[40];
    std::memcpy(expand_in, seed.data(), 32);
    for (uint64_t blake_index{0}; blake_index < 2048; ++blake_index) {
        WriteLE64(expand_in + 32, blake_index);
        Assert(0 == blake2b_nokey(block, 64, expand_in, sizeof(expand_in)));
        std::memcpy(stream_bytes.data() + blake_index * 64, block, 64);
    }
    matrix_a.assign(stream_bytes.begin(), stream_bytes.begin() + FP8_MATRIX_BYTES);
    matrix_b.assign(stream_bytes.begin() + FP8_MATRIX_BYTES, stream_bytes.end());
    for (auto* matrix : {&matrix_a, &matrix_b}) {
        for (uint8_t& byte : *matrix) {
            if ((byte & 0x7F) == 0x7F) {
                byte = static_cast<uint8_t>((byte & 0x80) | 0x7E);
            }
        }
    }
}

bool Fp8QmmaK32(std::span<const uint8_t> a_lane_k32, std::span<const uint8_t> b_lane_k32,
                float accumulator, float& out)
{
    if (a_lane_k32.size() != static_cast<size_t>(FP8_TILE_K) ||
        b_lane_k32.size() != static_cast<size_t>(FP8_TILE_K)) {
        return false;
    }

    ProductTerm products[FP8_TILE_K];
    for (int lane{0}; lane < FP8_TILE_K; ++lane) {
        if (!FillProductTerm(a_lane_k32[lane], b_lane_k32[lane], products[lane])) return false;
    }

    std::optional<float> immediate;
    std::optional<IeeeFp32Finite> accumulator_finite;
    std::visit(VisitArms{
                   [&](IeeeFp32NaN) { immediate = std::numeric_limits<float>::quiet_NaN(); },
                   [&](const IeeeFp32Inf& inf) {
                       immediate = inf.negative ? -std::numeric_limits<float>::infinity()
                                                : std::numeric_limits<float>::infinity();
                   },
                   [&](IeeeFp32Zero) {},
                   [&](const IeeeFp32Finite& finite) { accumulator_finite = finite; },
               },
               ClassifyIeeeFp32(accumulator));
    if (immediate) {
        out = *immediate;
        return true;
    }

    bool any{accumulator_finite.has_value()};
    int32_t exponent_max{accumulator_finite ? accumulator_finite->unbiased_exponent
                                            : std::numeric_limits<int32_t>::min()};
    for (int lane{0}; lane < FP8_TILE_K; ++lane) {
        if (products[lane].zero) continue;
        any = true;
        if (exponent_max == std::numeric_limits<int32_t>::min() ||
            products[lane].unbiased_exponent > exponent_max) {
            exponent_max = products[lane].unbiased_exponent;
        }
    }
    if (!any) {
        out = 0.0f;
        return true;
    }

    static constexpr int64_t kTermMax{int64_t{4} << FP8_FDA_FRAC};
    int64_t acc{0};
    auto add_term = [&](bool negative, int32_t unbiased_exponent, uint64_t significand_fda) {
        const int downshift{exponent_max - unbiased_exponent};
        Assert(downshift >= 0);
        uint64_t aligned{downshift >= 63 ? 0 : (significand_fda >> downshift)};
        Assert(aligned <= static_cast<uint64_t>(kTermMax));
        const int64_t term{negative ? -static_cast<int64_t>(aligned) : static_cast<int64_t>(aligned)};
        if (term > 0) {
            Assert(acc <= std::numeric_limits<int64_t>::max() - term);
        } else {
            Assert(acc >= std::numeric_limits<int64_t>::min() - term);
        }
        acc += term;
    };
    if (accumulator_finite) {
        add_term(accumulator_finite->negative, accumulator_finite->unbiased_exponent,
                 accumulator_finite->significand_fda);
    }
    for (int lane{0}; lane < FP8_TILE_K; ++lane) {
        if (!products[lane].zero) {
            add_term(products[lane].negative, products[lane].unbiased_exponent,
                     products[lane].significand_fda);
        }
    }
    out = NormalizeRzFp32(acc, exponent_max - FP8_FDA_FRAC);
    return true;
}

bool Fp8TiledMma(std::span<const uint8_t> matrix_a, std::span<const uint8_t> matrix_b, std::vector<float>& matrix_c)
{
    if (matrix_a.size() != static_cast<size_t>(FP8_MATRIX_BYTES) ||
        matrix_b.size() != static_cast<size_t>(FP8_MATRIX_BYTES)) {
        return false;
    }
    matrix_c.assign(FP8_MATRIX_BYTES, 0.0f);
    uint8_t a_lane[FP8_TILE_K];
    uint8_t b_lane[FP8_TILE_K];
    for (int k_tile{0}; k_tile < FP8_KT; ++k_tile) {
        for (int m_tile{0}; m_tile < FP8_MT; ++m_tile) {
            for (int n_tile{0}; n_tile < FP8_NT; ++n_tile) {
                for (int row_in_tile{0}; row_in_tile < FP8_TILE_M; ++row_in_tile) {
                    for (int col_in_tile{0}; col_in_tile < FP8_TILE_N; ++col_in_tile) {
                        const int row{m_tile * FP8_TILE_M + row_in_tile};
                        const int col{n_tile * FP8_TILE_N + col_in_tile};
                        for (int k_in_tile{0}; k_in_tile < FP8_TILE_K; ++k_in_tile) {
                            const int k{k_tile * FP8_TILE_K + k_in_tile};
                            a_lane[k_in_tile] = matrix_a[row * FP8_DIM + k];
                            b_lane[k_in_tile] = matrix_b[k * FP8_DIM + col];
                        }
                        float out;
                        if (!Fp8QmmaK32(std::span<const uint8_t>{a_lane, FP8_TILE_K},
                                        std::span<const uint8_t>{b_lane, FP8_TILE_K},
                                        matrix_c[row * FP8_DIM + col], out)) {
                            return false;
                        }
                        matrix_c[row * FP8_DIM + col] = out;
                    }
                }
            }
        }
    }
    return true;
}

std::optional<std::vector<uint8_t>> Fp8QuantizeC(std::span<const float> matrix_c)
{
    if (matrix_c.size() != static_cast<size_t>(FP8_MATRIX_BYTES)) return std::nullopt;
    std::vector<uint8_t> packed(FP8_MATRIX_BYTES);
    for (int i{0}; i < FP8_MATRIX_BYTES; ++i) {
        packed[i] = QuantizeE4M3FN(matrix_c[i]);
    }
    return packed;
}

uint256 Fp8PackedCDigest(std::span<const uint8_t> packed_c)
{
    static constexpr char kDomain[]{"gfcn-fp8-gym-out-v2"};
    std::vector<unsigned char> msg(19 + packed_c.size());
    std::memcpy(msg.data(), kDomain, 19);
    std::memcpy(msg.data() + 19, packed_c.data(), packed_c.size());
    uint256 digest;
    Assert(0 == blake2b_nokey(digest.begin(), 32, msg.data(), msg.size()));
    return digest;
}

std::optional<uint256> Fp8GymDigest(const CBlockHeader& header)
{
    std::vector<uint8_t> matrix_a, matrix_b;
    Fp8ExpandAB(header, matrix_a, matrix_b);
    std::vector<float> matrix_c;
    if (!Fp8TiledMma(matrix_a, matrix_b, matrix_c)) return std::nullopt;
    const auto packed{Fp8QuantizeC(matrix_c)};
    if (!packed) return std::nullopt;
    return Fp8PackedCDigest(*packed);
}

} // namespace Consensus
