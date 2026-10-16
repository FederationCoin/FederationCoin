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

namespace Consensus {
namespace {

struct E4Term {
    bool zero{true};
    bool neg{false};
    int32_t exp{0};
    uint32_t mag3{0};
};

bool ParseE4M3FN(uint8_t b, E4Term& t)
{
    const unsigned s{static_cast<unsigned>((b >> 7) & 1)};
    const unsigned e{static_cast<unsigned>((b >> 3) & 15)};
    const unsigned m{static_cast<unsigned>(b & 7)};
    if (e == 15 && m == 7) return false;
    t.neg = s != 0;
    if (e == 0 && m == 0) {
        t.zero = true;
        t.exp = 0;
        t.mag3 = 0;
        return true;
    }
    t.zero = false;
    if (e == 0) {
        t.mag3 = m;
        t.exp = -6;
    } else {
        t.mag3 = 8 + m;
        t.exp = static_cast<int32_t>(e) - 7;
    }
    return true;
}

/** value = signed_mag * 2^scale, RZ to binary32 (truncate at bit 23 of the
 *  normalized significand). Origin: QMMA FDA F=25; |signed_mag| is at most
 *  33 * (4 << 25). Asserts that bound. */
float NormalizeRzFp32(int64_t signed_mag, int scale)
{
    static constexpr int64_t kTermMax{int64_t{4} << FP8_FDA_FRAC};
    static constexpr int64_t kSumMax{33 * kTermMax};
    Assert(signed_mag >= -kSumMax && signed_mag <= kSumMax);
    if (signed_mag == 0) return 0.0f;
    const bool neg{signed_mag < 0};
    const uint64_t mag{static_cast<uint64_t>(neg ? -signed_mag : signed_mag)};
    const int k{63 - static_cast<int>(std::countl_zero(mag))};
    const int32_t unb{scale + k};
    uint32_t bits{neg ? 0x80000000u : 0u};
    if (unb >= 128) {
        bits |= 0x7f800000u;
        return std::bit_cast<float>(bits);
    }
    if (unb <= -127) {
        const int sl{scale + 149};
        uint64_t stored{0};
        if (sl >= 0) {
            if (sl >= 64 || (mag << sl) >> sl != mag) {
                stored = 0;
            } else {
                stored = mag << sl;
            }
        } else {
            const int sr{-sl};
            stored = sr >= 64 ? 0 : (mag >> sr);
        }
        if (stored >= (uint64_t{1} << 23)) stored = (uint64_t{1} << 23) - 1;
        bits |= static_cast<uint32_t>(stored);
        return std::bit_cast<float>(bits);
    }
    uint32_t mant24;
    if (k >= 23) {
        mant24 = static_cast<uint32_t>(mag >> (k - 23));
    } else {
        mant24 = static_cast<uint32_t>(mag << (23 - k));
    }
    const uint32_t exp_field{static_cast<uint32_t>(unb + 127)};
    bits |= (exp_field << 23) | (mant24 & 0x7fffffu);
    return std::bit_cast<float>(bits);
}

void UnpackFp32(float c, bool& nan, bool& inf, bool& neg, bool& zero, int32_t& exp, uint64_t& sig)
{
    const uint32_t u{std::bit_cast<uint32_t>(c)};
    neg = (u >> 31) != 0;
    const int e{static_cast<int>((u >> 23) & 255)};
    const uint32_t m{u & 0x7fffffu};
    nan = false;
    inf = false;
    zero = false;
    if (e == 255) {
        nan = m != 0;
        inf = m == 0;
        exp = 0;
        sig = 0;
        return;
    }
    if (e == 0 && m == 0) {
        zero = true;
        exp = 0;
        sig = 0;
        return;
    }
    if (e == 0) {
        exp = -126;
        sig = static_cast<uint64_t>(m) << (FP8_FDA_FRAC - 23);
        return;
    }
    exp = e - 127;
    sig = (uint64_t{0x800000} + m) << (FP8_FDA_FRAC - 23);
}

} // namespace

std::optional<float> DecodeE4M3FN(uint8_t b)
{
    E4Term t;
    if (!ParseE4M3FN(b, t)) return std::nullopt;
    if (t.zero) return 0.0f;
    const float mag{std::ldexp(static_cast<float>(t.mag3), t.exp - 3)};
    return t.neg ? -mag : mag;
}

uint8_t QuantizeE4M3FN(float x)
{
    const uint32_t u{std::bit_cast<uint32_t>(x)};
    const bool neg{(u >> 31) != 0};
    const int e{static_cast<int>((u >> 23) & 255)};
    const uint32_t m{u & 0x7fffffu};
    if (e == 255) {
        if (m != 0) return neg ? uint8_t{0xFF} : uint8_t{0x7F};
        return neg ? uint8_t{0xFE} : uint8_t{0x7E};
    }
    const bool sign{neg};
    if (e == 0 && m == 0) return sign ? uint8_t{0x80} : uint8_t{0x00};
    float mag{std::fabs(x)};
    if (mag > 448.0f) return sign ? uint8_t{0xFE} : uint8_t{0x7E};

    uint8_t best{0};
    float best_dist{std::numeric_limits<float>::infinity()};
    uint8_t best_mant{0};
    for (int code{0}; code <= 0x7E; ++code) {
        const auto decoded{DecodeE4M3FN(static_cast<uint8_t>(code))};
        if (!decoded) continue;
        const float d{std::fabs(mag - *decoded)};
        const uint8_t mant{static_cast<uint8_t>(code & 7)};
        if (d < best_dist) {
            best_dist = d;
            best = static_cast<uint8_t>(code);
            best_mant = mant;
        } else if (d == best_dist) {
            if ((mant % 2 == 0) && (best_mant % 2 != 0)) {
                best = static_cast<uint8_t>(code);
                best_mant = mant;
            } else if ((mant % 2 == 0) && (best_mant % 2 == 0) && code < best) {
                best = static_cast<uint8_t>(code);
                best_mant = mant;
            }
        }
    }
    if (best == 0) return sign ? uint8_t{0x80} : uint8_t{0x00};
    return sign ? static_cast<uint8_t>(best | 0x80) : best;
}

void Fp8ExpandAB(const CBlockHeader& header, std::vector<uint8_t>& a, std::vector<uint8_t>& b)
{
    DataStream ss;
    ss << header;
    static constexpr char kDomain[]{"gfcn-fp8-gym-v2"};
    std::array<unsigned char, 16 + 164> seed_msg{};
    std::memcpy(seed_msg.data(), kDomain, 16);
    Assert(ss.size() == 164);
    std::memcpy(seed_msg.data() + 16, ss.data(), 164);
    uint256 seed;
    Assert(0 == blake2b_nokey(seed.begin(), 32, seed_msg.data(), seed_msg.size()));

    std::vector<uint8_t> stream(2 * FP8_MATRIX_BYTES);
    unsigned char block[64];
    unsigned char in[40];
    std::memcpy(in, seed.data(), 32);
    for (uint64_t i{0}; i < 2048; ++i) {
        WriteLE64(in + 32, i);
        Assert(0 == blake2b_nokey(block, 64, in, sizeof(in)));
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

bool Fp8QmmaK32(std::span<const uint8_t> a_k, std::span<const uint8_t> b_k, float c, float& out)
{
    if (a_k.size() != static_cast<size_t>(FP8_TILE_K) || b_k.size() != static_cast<size_t>(FP8_TILE_K)) {
        return false;
    }

    struct Term {
        bool zero{true};
        bool neg{false};
        int32_t exp{0};
        uint64_t sig{0};
    };
    Term prods[FP8_TILE_K];
    for (int k{0}; k < FP8_TILE_K; ++k) {
        E4Term ta, tb;
        if (!ParseE4M3FN(a_k[k], ta) || !ParseE4M3FN(b_k[k], tb)) return false;
        if (ta.zero || tb.zero) continue;
        Assert(ta.mag3 <= 15 && tb.mag3 <= 15);
        const uint32_t mag6{ta.mag3 * tb.mag3};
        Assert(mag6 <= 225);
        prods[k].zero = false;
        prods[k].neg = ta.neg != tb.neg;
        prods[k].exp = ta.exp + tb.exp;
        prods[k].sig = static_cast<uint64_t>(mag6) << (FP8_FDA_FRAC - 6);
    }

    bool c_nan{false}, c_inf{false}, c_neg{false}, c_zero{false};
    int32_t c_exp{0};
    uint64_t c_sig{0};
    UnpackFp32(c, c_nan, c_inf, c_neg, c_zero, c_exp, c_sig);
    if (c_nan) {
        out = std::numeric_limits<float>::quiet_NaN();
        return true;
    }
    if (c_inf) {
        out = c_neg ? -std::numeric_limits<float>::infinity() : std::numeric_limits<float>::infinity();
        return true;
    }

    bool any{!c_zero};
    int32_t e_max{c_zero ? std::numeric_limits<int32_t>::min() : c_exp};
    for (int k{0}; k < FP8_TILE_K; ++k) {
        if (prods[k].zero) continue;
        any = true;
        if (e_max == std::numeric_limits<int32_t>::min() || prods[k].exp > e_max) {
            e_max = prods[k].exp;
        }
    }
    if (!any) {
        out = 0.0f;
        return true;
    }

    static constexpr int64_t kTermMax{int64_t{4} << FP8_FDA_FRAC};
    int64_t acc{0};
    auto add_term = [&](bool neg, int32_t exp, uint64_t sig) {
        const int d{e_max - exp};
        Assert(d >= 0);
        uint64_t aligned{d >= 63 ? 0 : (sig >> d)};
        Assert(aligned <= static_cast<uint64_t>(kTermMax));
        const int64_t term{neg ? -static_cast<int64_t>(aligned) : static_cast<int64_t>(aligned)};
        if (term > 0) {
            Assert(acc <= std::numeric_limits<int64_t>::max() - term);
        } else {
            Assert(acc >= std::numeric_limits<int64_t>::min() - term);
        }
        acc += term;
    };
    if (!c_zero) add_term(c_neg, c_exp, c_sig);
    for (int k{0}; k < FP8_TILE_K; ++k) {
        if (!prods[k].zero) add_term(prods[k].neg, prods[k].exp, prods[k].sig);
    }
    out = NormalizeRzFp32(acc, e_max - FP8_FDA_FRAC);
    return true;
}

bool Fp8TiledMma(std::span<const uint8_t> a, std::span<const uint8_t> b, std::vector<float>& c)
{
    if (a.size() != static_cast<size_t>(FP8_MATRIX_BYTES) || b.size() != static_cast<size_t>(FP8_MATRIX_BYTES)) {
        return false;
    }
    c.assign(FP8_MATRIX_BYTES, 0.0f);
    uint8_t a_lane[FP8_TILE_K];
    uint8_t b_lane[FP8_TILE_K];
    for (int kt{0}; kt < FP8_KT; ++kt) {
        for (int mt{0}; mt < FP8_MT; ++mt) {
            for (int nt{0}; nt < FP8_NT; ++nt) {
                for (int i{0}; i < FP8_TILE_M; ++i) {
                    for (int j{0}; j < FP8_TILE_N; ++j) {
                        const int row{mt * FP8_TILE_M + i};
                        const int col{nt * FP8_TILE_N + j};
                        for (int kk{0}; kk < FP8_TILE_K; ++kk) {
                            const int k{kt * FP8_TILE_K + kk};
                            a_lane[kk] = a[row * FP8_DIM + k];
                            b_lane[kk] = b[k * FP8_DIM + col];
                        }
                        float out;
                        if (!Fp8QmmaK32(std::span<const uint8_t>{a_lane, FP8_TILE_K},
                                        std::span<const uint8_t>{b_lane, FP8_TILE_K},
                                        c[row * FP8_DIM + col], out)) {
                            return false;
                        }
                        c[row * FP8_DIM + col] = out;
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
        packed[i] = QuantizeE4M3FN(c[i]);
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
    std::vector<uint8_t> a, b;
    Fp8ExpandAB(header, a, b);
    std::vector<float> c;
    if (!Fp8TiledMma(a, b, c)) return std::nullopt;
    const auto packed{Fp8QuantizeC(c)};
    if (!packed) return std::nullopt;
    return Fp8PackedCDigest(*packed);
}

} // namespace Consensus
