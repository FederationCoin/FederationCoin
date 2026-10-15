// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Kind-2 consensus: this translation unit is the gym. Keep contraction off
// so acc = acc + (av * bv) stays two operations on every compiler we ship.
#if defined(_MSC_VER)
#pragma float_control(precise, on)
#else
#pragma STDC FP_CONTRACT OFF
#endif

#include <consensus/work/fp8_gym.h>

#include <crypto/blake2b.h>
#include <crypto/common.h>
#include <hash.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>

#include <cmath>
#include <cstring>
#include <limits>

namespace Consensus {
namespace {

bool IsInfOrNan(float x)
{
    return !std::isfinite(x);
}

} // namespace

std::optional<float> DecodeE4M3FN(uint8_t b)
{
    const unsigned s{(b >> 7) & 1};
    const unsigned e{(b >> 3) & 15};
    const unsigned m{b & 7};
    // E4M3FN: NaN is 0x7F/0xFF only (e=15, m=7). 0x7E is max finite 448.
    if (e == 15 && m == 7) return std::nullopt;
    float mag;
    if (e == 0 && m == 0) {
        mag = 0.0f;
    } else if (e == 0) {
        mag = static_cast<float>(m) * std::ldexp(1.0f, -9);
    } else {
        mag = static_cast<float>(8 + m) * std::ldexp(1.0f, static_cast<int>(e) - 10);
    }
    return s ? -mag : mag;
}

std::optional<uint8_t> QuantizeE4M3FN(float x)
{
    if (IsInfOrNan(x)) return std::nullopt;
    const bool neg{std::signbit(x)};
    float mag{std::fabs(x)};
    if (mag == 0.0f) return uint8_t{0x00};
    if (mag > 448.0f) return neg ? uint8_t{0xFE} : uint8_t{0x7E};

    uint8_t best{0};
    float best_dist{std::numeric_limits<float>::infinity()};
    uint8_t best_mant{0};
    for (int code{0}; code <= 0x7E; ++code) {
        const auto decoded{DecodeE4M3FN(static_cast<uint8_t>(code))};
        if (!decoded) continue;
        const float d{std::fabs(mag - *decoded)};
        const uint8_t mant{static_cast<uint8_t>(code & 7)};
        if (d < best_dist || (d == best_dist && (mant % 2 == 0) && (best_mant % 2 != 0))) {
            best_dist = d;
            best = static_cast<uint8_t>(code);
            best_mant = mant;
        } else if (d == best_dist && (mant % 2 == 0) && (best_mant % 2 == 0) && code < best) {
            best = static_cast<uint8_t>(code);
            best_mant = mant;
        }
    }
    if (best == 0) return uint8_t{0x00};
    return neg ? static_cast<uint8_t>(best | 0x80) : best;
}

void Fp8ExpandAB(const CBlockHeader& header, std::vector<uint8_t>& a, std::vector<uint8_t>& b)
{
    DataStream ss;
    ss << header;
    static constexpr char kDomain[]{"gfcn-fp8-gym-v1"};
    std::array<unsigned char, 16 + 164> seed_msg{};
    std::memcpy(seed_msg.data(), kDomain, 16);
    assert(ss.size() == 164);
    std::memcpy(seed_msg.data() + 16, ss.data(), 164);
    uint256 seed;
    assert(0 == blake2b_nokey(seed.begin(), 32, seed_msg.data(), seed_msg.size()));

    std::vector<uint8_t> stream(2 * FP8_MATRIX_BYTES);
    unsigned char block[64];
    unsigned char in[40];
    std::memcpy(in, seed.data(), 32);
    for (uint64_t i{0}; i < 2048; ++i) {
        WriteLE64(in + 32, i);
        assert(0 == blake2b_nokey(block, 64, in, sizeof(in)));
        std::memcpy(stream.data() + i * 64, block, 64);
    }
    a.assign(stream.begin(), stream.begin() + FP8_MATRIX_BYTES);
    b.assign(stream.begin() + FP8_MATRIX_BYTES, stream.end());
    for (auto* mat : {&a, &b}) {
        for (uint8_t& byte : *mat) {
            if ((byte & 0x7F) == 0x7F) {
                byte = static_cast<uint8_t>((byte & 0x80) | 0x7E);
            }
        }
    }
}

bool Fp8TiledMma(std::span<const uint8_t> a, std::span<const uint8_t> b, std::vector<float>& c)
{
    if (a.size() != static_cast<size_t>(FP8_MATRIX_BYTES) || b.size() != static_cast<size_t>(FP8_MATRIX_BYTES)) {
        return false;
    }
    c.assign(FP8_MATRIX_BYTES, 0.0f);
    auto A = [&](int row, int col) -> uint8_t { return a[row * FP8_DIM + col]; };
    auto B = [&](int row, int col) -> uint8_t { return b[row * FP8_DIM + col]; };
    auto C = [&](int row, int col) -> float& { return c[row * FP8_DIM + col]; };

    for (int kt{0}; kt < FP8_KT; ++kt) {
        for (int mt{0}; mt < FP8_MT; ++mt) {
            for (int nt{0}; nt < FP8_NT; ++nt) {
                for (int i{0}; i < FP8_TILE_M; ++i) {
                    for (int j{0}; j < FP8_TILE_N; ++j) {
                        float acc{C(mt * FP8_TILE_M + i, nt * FP8_TILE_N + j)};
                        for (int kk{0}; kk < FP8_TILE_K; ++kk) {
                            const auto av{DecodeE4M3FN(A(mt * FP8_TILE_M + i, kt * FP8_TILE_K + kk))};
                            const auto bv{DecodeE4M3FN(B(kt * FP8_TILE_K + kk, nt * FP8_TILE_N + j))};
                            if (!av || !bv) return false;
                            const float prod{*av * *bv};
                            if (IsInfOrNan(prod)) return false;
                            acc = acc + prod;
                            if (IsInfOrNan(acc)) return false;
                        }
                        C(mt * FP8_TILE_M + i, nt * FP8_TILE_N + j) = acc;
                    }
                }
            }
        }
    }
    return true;
}

std::optional<std::vector<uint8_t>> Fp8QuantizeC(std::span<const float> c)
{
    if (c.size() != static_cast<size_t>(FP8_MATRIX_BYTES)) return std::nullopt;
    std::vector<uint8_t> packed(FP8_MATRIX_BYTES);
    for (int i{0}; i < FP8_MATRIX_BYTES; ++i) {
        const auto q{QuantizeE4M3FN(c[i])};
        if (!q) return std::nullopt;
        packed[i] = *q;
    }
    return packed;
}

uint256 Fp8PackedCDigest(std::span<const uint8_t> packed_c)
{
    static constexpr char kDomain[]{"gfcn-fp8-gym-out-v1"};
    std::vector<unsigned char> msg(19 + packed_c.size());
    std::memcpy(msg.data(), kDomain, 19);
    std::memcpy(msg.data() + 19, packed_c.data(), packed_c.size());
    uint256 digest;
    assert(0 == blake2b_nokey(digest.begin(), 32, msg.data(), msg.size()));
    return digest;
}

std::optional<uint256> Fp8GymDigest(const CBlockHeader& header)
{
    std::vector<uint8_t> a, b;
    Fp8ExpandAB(header, a, b);
    std::vector<float> c;
    if (!Fp8TiledMma(a, b, c)) return std::nullopt;
    const auto packed{Fp8QuantizeC(c)};
    if (!packed) return std::nullopt;
    return Fp8PackedCDigest(*packed);
}

} // namespace Consensus
