// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/work/poseidon2.h>

#include <consensus/checked_arith.h>
#include <consensus/flex_weight.h>
#include <crypto/blake2b.h>
#include <crypto/common.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>

#include <cstring>

namespace Consensus {
namespace {

/** 2^32 - 1. 2^64 ≡ EPSILON (mod P). */
static constexpr uint64_t EPSILON{0xFFFFFFFFULL};

struct Goldilocks {
    uint64_t v{0};
    static Goldilocks from_raw(uint64_t x)
    {
        Goldilocks o;
        o.v = x >= GOLDILOCKS_P ? x - GOLDILOCKS_P : x;
        return o;
    }
    static Goldilocks from_u64(uint64_t x) { return from_raw(x); }
    uint64_t canonical() const { return v >= GOLDILOCKS_P ? v - GOLDILOCKS_P : v; }
};

Goldilocks operator+(Goldilocks a, Goldilocks b)
{
    const uint64_t sum{WrappingAddU64(a.v, b.v)};
    const bool over{sum < a.v};
    return Goldilocks::from_raw(over ? WrappingAddU64(sum, EPSILON) : sum);
}

Goldilocks operator*(Goldilocks a, Goldilocks b)
{
    const WideProduct z{Mul128(a.v, b.v)};
    const uint64_t x_lo{z.lo};
    const uint64_t x_hi{z.hi};
    const uint64_t x_hi_hi{x_hi >> 32};
    const uint64_t x_hi_lo{x_hi & EPSILON};
    const bool borrow{x_lo < x_hi_hi};
    uint64_t t0{WrappingSubU64(x_lo, x_hi_hi)};
    if (borrow) {
        t0 = WrappingSubU64(t0, EPSILON);
    }
    const uint64_t t1{x_hi_lo * EPSILON};
    const uint64_t t2{WrappingAddU64(t0, t1)};
    const bool carry{t2 < t0};
    return Goldilocks::from_raw(carry ? WrappingAddU64(t2, EPSILON) : t2);
}

Goldilocks Double(Goldilocks x) { return x + x; }

Goldilocks Exp7(Goldilocks x)
{
    const Goldilocks x2{x * x};
    const Goldilocks x4{x2 * x2};
    return x4 * x2 * x;
}

static constexpr uint64_t INTERNAL_CONSTANTS[POSEIDON2_INTERNAL_ROUNDS] = {
    0x97f7798a784ad863, 0xd1d2bf082f60d4f0, 0x69a377a79f9ad206, 0xa9d06906a3858e24,
    0x295275001eede5b5, 0x5874e441117bd746, 0x8a084bbba8ed86cc, 0x3defd7645cde6425,
    0x3998cfe6871cc137, 0x3e52ef8bca48314a, 0x964a209f85dc9ecc, 0x3fcc9ee82cc4577e,
    0x8e79b4a5d0096d6d, 0x8492362ad2392556, 0xee72f470262574d6, 0x1e0e18496da2444a,
    0x0f3a74bf215eaac6, 0x1b061b76a1c0ded3, 0x192c42d86803d7a6, 0xf6d49ff997ae0260,
    0x3ec372e7a0fa3786, 0x5538cdf4f23445d3,
};

static constexpr uint64_t MATRIX_DIAG[POSEIDON2_WIDTH] = {
    0xc3b6c08e23ba9300, 0xd84b5de94a324fb6, 0x0d0c371c5b35b84f, 0x7964f570e7188037,
    0x5daf18bbd996604b, 0x6743bc47b9595257, 0x5528b9362c59bb70, 0xac45e25b7127b68b,
    0xa2077d7dfbb606b5, 0xf3faac6faee378ae, 0x0c6388b51545e883, 0xd27dbb6944917b60,
};

static constexpr uint64_t INITIAL_EXTERNAL[4][POSEIDON2_WIDTH] = {
    {0xc002e770975b1607, 0xbca51a8dfe14593a, 0x72938dfbe774f7f9, 0xe4f2fe29e03234ac,
     0xd5e0ba2f541b6449, 0xec33b868f3cc46c1, 0x486dcb55419d475a, 0x6c1cb2a358cc24f1,
     0xe3f30d509a1436bb, 0xd9a64f068dca7c29, 0xe59b3f57aabba1ae, 0x2a3dd4505b478fdc},
    {0xada1f8dc7676ed25, 0x2711aa8b5509d516, 0x4ae6acd0c9c92897, 0x56eb3d6b5256d67a,
     0x1f7a9d55923bf51e, 0x3600427d397a7f68, 0xe5076df75b72c3d0, 0xfcd59aa12c6090ad,
     0xcd895e8c68b57a9e, 0x41df7ef9d730ae3e, 0xee3e2b889abe977d, 0xd29bb7edbeb9c405},
    {0x7d5c08eef608e382, 0x89ae889caaf0802c, 0xb35a8e976d2af617, 0xdb14234eafaf5173,
     0x78f04462d48b1c98, 0x265293b0e47ce88a, 0x999a649b69b9d32f, 0x64b0a186698e01d3,
     0xee0b22d0dfae8bb8, 0x4fd53e50ca04a7ee, 0x5762bfe181f25047, 0xf51593e2beb5e3bd},
    {0x1e5e2b5760e32477, 0x622462a1f9aaaeed, 0xaa284b3ecdb222ae, 0x63c8e72f542bf3fc,
     0x3ba588cacb43b5e0, 0x23eda6f3c99150dd, 0xaad3bea4baac9a5a, 0xe9da8d699b94184a,
     0xcdb13f4cd93e024c, 0x902cbd0956f655e3, 0x5b4e40ffc759532f, 0xde795c20a2357af7},
};

static constexpr uint64_t TERMINAL_EXTERNAL[4][POSEIDON2_WIDTH] = {
    {0x7b72c539e0ea4c6e, 0x144573dae2ce9976, 0x802028b68f35fc88, 0x6d36c5022c4fe7c2,
     0xa205d0ffa9b9def3, 0xf6e7e38b1ea6ba2f, 0x34f7909ae5258d64, 0xb0464d9d77b97fca,
     0x64ddb9d5de7e00a6, 0x0ed0d75c27975d97, 0x1cbb36f11127338b, 0x6673e505cfd0b6ba},
    {0x605f902830872e01, 0x3fd5eb927e95fe4f, 0xe81025b5a24c69cd, 0xf7d0ce75de23f74e,
     0xf39942b6a8585089, 0x6d808a08f7b71df6, 0xf8806b6588f49a8b, 0x57df2d8c2a32107a,
     0x16e7c2074d654a2d, 0x213de241fcf33835, 0xb0f2b8905a0976f6, 0xd8e3cf2bbd355417},
    {0xe498691679d9330f, 0x763b45d2a3821b28, 0x0908bf65eb0a1f0d, 0x7691eb2d194b24f4,
     0x0e43551233ae13b2, 0x93c393dbfc2fe76f, 0x98f607485d48cdea, 0xe3d95f30309819c0,
     0x1ef581a93eaf6acf, 0x0b24c1b7a030fca4, 0x624370be5670b327, 0x5f1e28615a11e486},
    {0xfe04051f909e042b, 0x7257e5b147fd3803, 0xe6ae134bb82f2e78, 0x5711fd5cf4784511,
     0xf83a42660c08c0bc, 0x2cd8c96d9a3ce855, 0x7d2ffb1bb0e17271, 0x85ae1528caea3811,
     0x52a345d5c7adb0b8, 0x504c4c51f3faee94, 0xbce34a649cfccaf9, 0xe0a3389266fb6dc9},
};

void ApplyMat4(Goldilocks x[4])
{
    const Goldilocks t01{x[0] + x[1]};
    const Goldilocks t23{x[2] + x[3]};
    const Goldilocks t0123{t01 + t23};
    const Goldilocks t01123{t0123 + x[1]};
    const Goldilocks t01233{t0123 + x[3]};
    x[3] = t01233 + Double(x[0]);
    x[1] = t01123 + Double(x[2]);
    x[0] = t01123 + t01;
    x[2] = t01233 + t23;
}

void ExternalLinear(Goldilocks state[POSEIDON2_WIDTH])
{
    for (unsigned c{0}; c < POSEIDON2_WIDTH; c += 4) {
        ApplyMat4(state + c);
    }
    Goldilocks sums[4]{Goldilocks{}, Goldilocks{}, Goldilocks{}, Goldilocks{}};
    for (unsigned j{0}; j < POSEIDON2_WIDTH; j += 4) {
        for (unsigned k{0}; k < 4; ++k) {
            sums[k] = sums[k] + state[j + k];
        }
    }
    for (unsigned i{0}; i < POSEIDON2_WIDTH; ++i) {
        state[i] = state[i] + sums[i % 4];
    }
}

void InternalLinear(Goldilocks state[POSEIDON2_WIDTH])
{
    Goldilocks sum{};
    for (unsigned i{0}; i < POSEIDON2_WIDTH; ++i) {
        sum = sum + state[i];
    }
    for (unsigned i{0}; i < POSEIDON2_WIDTH; ++i) {
        state[i] = sum + state[i] * Goldilocks::from_u64(MATRIX_DIAG[i]);
    }
}

void ExternalRound(Goldilocks state[POSEIDON2_WIDTH], const uint64_t rc[POSEIDON2_WIDTH])
{
    for (unsigned i{0}; i < POSEIDON2_WIDTH; ++i) {
        state[i] = Exp7(state[i] + Goldilocks::from_u64(rc[i]));
    }
    ExternalLinear(state);
}

void InternalRound(Goldilocks state[POSEIDON2_WIDTH], uint64_t rc)
{
    state[0] = Exp7(state[0] + Goldilocks::from_u64(rc));
    InternalLinear(state);
}

void Permute(Goldilocks state[POSEIDON2_WIDTH])
{
    ExternalLinear(state);
    for (unsigned r{0}; r < 4; ++r) {
        ExternalRound(state, INITIAL_EXTERNAL[r]);
    }
    for (unsigned r{0}; r < POSEIDON2_INTERNAL_ROUNDS; ++r) {
        InternalRound(state, INTERNAL_CONSTANTS[r]);
    }
    for (unsigned r{0}; r < 4; ++r) {
        ExternalRound(state, TERMINAL_EXTERNAL[r]);
    }
}

void DigestToBytes(const Goldilocks state[POSEIDON2_WIDTH], unsigned char out[32])
{
    for (unsigned i{0}; i < POSEIDON2_OUTPUT; ++i) {
        const uint64_t w{state[i].canonical()};
        WriteLE64(out + i * 8, w);
    }
}

struct Sponge {
    Goldilocks state[POSEIDON2_WIDTH]{};
    Goldilocks buf[POSEIDON2_RATE]{};
    unsigned buf_len{0};

    void AbsorbFull()
    {
        for (unsigned i{0}; i < POSEIDON2_RATE; ++i) {
            state[i] = state[i] + buf[i];
        }
        Permute(state);
        for (unsigned i{0}; i < POSEIDON2_RATE; ++i) {
            buf[i] = Goldilocks{};
        }
        buf_len = 0;
    }

    void Push(Goldilocks x)
    {
        buf[buf_len] = x;
        ++buf_len;
        if (buf_len == POSEIDON2_RATE) AbsorbFull();
    }

    void AbsorbBytes(std::span<const unsigned char> input)
    {
        size_t pos{0};
        while (pos + 4 <= input.size()) {
            Push(Goldilocks::from_u64(ReadLE32(input.data() + pos)));
            pos += 4;
        }
        unsigned char last[4]{};
        const size_t rem{input.size() - pos};
        if (rem) std::memcpy(last, input.data() + pos, rem);
        last[rem] = 1;
        Push(Goldilocks::from_u64(ReadLE32(last)));
    }

    void FinalizePad()
    {
        Push(Goldilocks::from_u64(1));
        while (buf_len != 0) {
            Push(Goldilocks::from_u64(0));
        }
    }
};

std::array<unsigned char, 32> HashBytesImpl(std::span<const unsigned char> input)
{
    Sponge s;
    s.AbsorbBytes(input);
    s.FinalizePad();
    std::array<unsigned char, 32> out{};
    DigestToBytes(s.state, out.data());
    return out;
}

std::array<unsigned char, 64> HashSqueezeTwiceImpl(std::span<const unsigned char> input)
{
    Sponge s;
    s.AbsorbBytes(input);
    s.FinalizePad();
    std::array<unsigned char, 64> out{};
    DigestToBytes(s.state, out.data());
    Permute(s.state);
    DigestToBytes(s.state, out.data() + 32);
    return out;
}

} // namespace

void Poseidon2Permute(std::array<uint64_t, POSEIDON2_WIDTH>& state)
{
    Goldilocks s[POSEIDON2_WIDTH];
    for (unsigned i{0}; i < POSEIDON2_WIDTH; ++i) {
        s[i] = Goldilocks::from_u64(state[i]);
    }
    Permute(s);
    for (unsigned i{0}; i < POSEIDON2_WIDTH; ++i) {
        state[i] = s[i].canonical();
    }
}

std::array<unsigned char, 32> Poseidon2HashBytes(std::span<const unsigned char> input)
{
    return HashBytesImpl(input);
}

std::array<unsigned char, 64> Poseidon2HashSqueezeTwice(std::span<const unsigned char> input)
{
    return HashSqueezeTwiceImpl(input);
}

std::array<unsigned char, 64> Poseidon2NonceOverlay(const CBlockHeader& header)
{
    std::array<unsigned char, 64> n{};
    WriteLE32(n.data() + 0, header.nNonce);
    WriteLE32(n.data() + 4, header.m_nonce2);
    WriteLE32(n.data() + 8, header.m_nonce3);
    std::memcpy(n.data() + 12, header.m_extranonce.data(), 16);
    WriteLE32(n.data() + 28, header.m_time_offset);
    std::memcpy(n.data() + 32, header.m_mm_rhs.data(), 32);
    return n;
}

uint256 Poseidon2Preimage(const CBlockHeader& header)
{
    CBlockHeader z{header};
    z.nNonce = 0;
    z.m_nonce2 = 0;
    z.m_nonce3 = 0;
    z.m_extranonce.SetNull();
    z.m_time_offset = 0;
    z.m_mm_rhs.SetNull();
    DataStream ss;
    ss << z;
    static constexpr char kDomain[]{"gfcn-poseidon2-pre-v1"};
    std::array<unsigned char, 20 + 164> msg{};
    std::memcpy(msg.data(), kDomain, 20);
    assert(ss.size() == 164);
    std::memcpy(msg.data() + 20, ss.data(), 164);
    uint256 pre;
    assert(0 == blake2b_nokey(pre.begin(), 32, msg.data(), msg.size()));
    return pre;
}

std::array<unsigned char, 64> Poseidon2WorkHash(const CBlockHeader& header)
{
    const uint256 pre{Poseidon2Preimage(header)};
    const auto nonce{Poseidon2NonceOverlay(header)};
    std::array<unsigned char, 96> in{};
    std::memcpy(in.data(), pre.data(), 32);
    std::memcpy(in.data() + 32, nonce.data(), 64);
    return Poseidon2HashSqueezeTwice(in);
}

} // namespace Consensus
