// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/work/kind.h>

#include <arith_uint256.h>
#include <consensus/work/fp8_gym.h>
#include <consensus/work/poseidon2.h>
#include <hash.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>
#include <util/check.h>

#include <cstring>
#include <limits>

namespace Consensus {
namespace {

bool XorKeyNull(const CBlockHeader& header)
{
    return header.m_xor_key.IsNull() && header.m_xor_key_mask_clear_bits == 0;
}

uint256 Uint256FromBE(std::span<const unsigned char> be32)
{
    Assert(be32.size() == 32);
    unsigned char le[32];
    for (int i{0}; i < 32; ++i) {
        le[i] = be32[31 - i];
    }
    return uint256{Span{le, 32}};
}

bool DigestMeetsTarget(const uint256& digest, unsigned int nBits, const uint256& pow_limit)
{
    bool fNegative{false};
    bool fOverflow{false};
    arith_uint256 bnTarget;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit)) {
        return false;
    }
    return UintToArith256(digest) < bnTarget;
}

class Blake2bWork final : public WorkKind
{
public:
    WorkKindTag Kind() const override { return WorkKindTag::BLAKE2B; }
    const char* Name() const override { return "blake2b"; }
    uint256 WorkDigest(const CBlockHeader& header) const override { return header.GetHash(); }
    bool TailRule(const CBlockHeader& header) const override { return true; }
    void PrepareTemplate(CBlockHeader& header) const override
    {
        header.m_xor_key.SetNull();
        header.m_xor_key_mask_clear_bits = 0;
    }
    bool Check(const CBlockHeader& header, unsigned int nBits, const Params& params) const override
    {
        return DigestMeetsTarget(WorkDigest(header), nBits, params.powLimitKind[0]);
    }
    unsigned int ExpectedNBits(const uint256& work_scale, const Params& params) const override
    {
        return CompactTargetForScale(0, work_scale, params);
    }
};

class Sha256dWork final : public WorkKind
{
public:
    WorkKindTag Kind() const override { return WorkKindTag::SHA256D; }
    const char* Name() const override { return "sha256d"; }
    uint256 WorkDigest(const CBlockHeader& header) const override
    {
        const auto ser{SerializeHeaderV2(header)};
        Assert(ser.size() == BLOCK_HEADER_V2_SERIALIZED_SIZE);
        return Sha256dBytes(std::span<const unsigned char>{ser.data(), 80});
    }
    bool TailRule(const CBlockHeader& header) const override
    {
        if (header.m_nonce2 != 0 || header.m_nonce3 != 0) return false;
        if (!header.m_extranonce.IsNull()) return false;
        if (header.m_time_offset != 0) return false;
        if (header.m_flags != 0) return false;
        if (!XorKeyNull(header)) return false;
        if (!header.m_mm_rhs.IsNull()) return false;
        return true;
    }
    void PrepareTemplate(CBlockHeader& header) const override
    {
        header.m_nonce2 = 0;
        header.m_nonce3 = 0;
        header.m_extranonce.SetNull();
        header.m_time_offset = 0;
        header.m_flags = 0;
        header.m_xor_key.SetNull();
        header.m_xor_key_mask_clear_bits = 0;
        header.m_mm_rhs.SetNull();
    }
    bool Check(const CBlockHeader& header, unsigned int nBits, const Params& params) const override
    {
        return DigestMeetsTarget(WorkDigest(header), nBits, params.powLimitKind[1]);
    }
    unsigned int ExpectedNBits(const uint256& work_scale, const Params& params) const override
    {
        return CompactTargetForScale(1, work_scale, params);
    }
};

class Fp8GymWork final : public WorkKind
{
public:
    WorkKindTag Kind() const override { return WorkKindTag::FP8_GYM; }
    const char* Name() const override { return "fp8gym"; }
    uint256 WorkDigest(const CBlockHeader& header) const override
    {
        const auto digest{Fp8GymDigest(header)};
        return digest.value_or(uint256{});
    }
    bool TailRule(const CBlockHeader& header) const override
    {
        if (header.m_flags != 0) return false;
        if (header.m_time_offset != 0) return false;
        if (!XorKeyNull(header)) return false;
        if (!header.m_mm_rhs.IsNull()) return false;
        return true;
    }
    void PrepareTemplate(CBlockHeader& header) const override
    {
        header.m_flags = 0;
        header.m_time_offset = 0;
        header.m_xor_key.SetNull();
        header.m_xor_key_mask_clear_bits = 0;
        header.m_mm_rhs.SetNull();
    }
    bool Check(const CBlockHeader& header, unsigned int nBits, const Params& params) const override
    {
        bool fNegative{false};
        bool fOverflow{false};
        arith_uint256 bnTarget;
        bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
        const arith_uint256 limit{UintToArith256(params.powLimitKind[2])};
        if (fNegative || bnTarget == 0 || fOverflow || bnTarget > limit) return false;
        const auto digest{Fp8GymDigest(header)};
        if (!digest) return false;
        return UintToArith256(*digest) < bnTarget;
    }
    unsigned int ExpectedNBits(const uint256& work_scale, const Params& params) const override
    {
        return CompactTargetForScale(2, work_scale, params);
    }
};

class Poseidon2Work final : public WorkKind
{
public:
    WorkKindTag Kind() const override { return WorkKindTag::POSEIDON2; }
    const char* Name() const override { return "poseidon2"; }
    uint256 WorkDigest(const CBlockHeader& header) const override
    {
        const auto h{Poseidon2WorkHash(header)};
        return Uint256FromBE(std::span<const unsigned char>{h.data(), 32});
    }
    bool TailRule(const CBlockHeader& header) const override
    {
        if (header.m_flags != 0) return false;
        return XorKeyNull(header);
    }
    void PrepareTemplate(CBlockHeader& header) const override
    {
        header.m_flags = 0;
        header.m_xor_key.SetNull();
        header.m_xor_key_mask_clear_bits = 0;
    }
    bool Check(const CBlockHeader& header, unsigned int nBits, const Params& params) const override
    {
        // U512 BE < target256<<256 iff high 256 < target256. Equality invalid.
        return DigestMeetsTarget(WorkDigest(header), nBits, params.powLimitKind[3]);
    }
    unsigned int ExpectedNBits(const uint256& work_scale, const Params& params) const override
    {
        return CompactTargetForScale(3, work_scale, params);
    }
};

const Blake2bWork g_blake2b;
const Sha256dWork g_sha256d;
const Fp8GymWork g_fp8;
const Poseidon2Work g_poseidon2;
const WorkKind* const g_kinds[WORK_KIND_COUNT] = {&g_blake2b, &g_sha256d, &g_fp8, &g_poseidon2};

} // namespace

const WorkKind* LookupWorkKind(WorkKindTag tag)
{
    const auto i{static_cast<size_t>(tag)};
    if (i >= WORK_KIND_COUNT) return nullptr;
    return g_kinds[i];
}

const WorkKind* WorkKindAt(size_t index)
{
    if (index >= WORK_KIND_COUNT) return nullptr;
    return g_kinds[index];
}

std::optional<WorkKindTag> DecodeWorkKindTag(uint32_t complete_version)
{
    if ((complete_version & CBlockHeader::VERSION_HEADER_V2_FLAG) == 0) return std::nullopt;
    if (complete_version & VERSION_WORK_RESERVED_MASK) return std::nullopt;
    return static_cast<WorkKindTag>((complete_version >> VERSION_WORK_KIND_SHIFT) & 3);
}

void ApplyWorkKindTag(CBlockHeader& header, WorkKindTag tag)
{
    header.m_header_v2 = true;
    uint32_t v{static_cast<uint32_t>(header.nVersion)};
    v &= ~VERSION_WORK_KIND_MASK;
    v |= static_cast<uint32_t>(tag) << VERSION_WORK_KIND_SHIFT;
    // Buried BIP66/CLTV require nVersion >= 4. ComputeBlockVersion already
    // sets TOP_BITS (0x20000000), which satisfies that. Forcing bit 2 on top
    // of TOP_BITS looks like unknown versionbit signaling.
    if ((v & 0x7FFFFFFFu) < 4) {
        v = (v & ~0xFFu) | 4;
    }
    header.nVersion = static_cast<int32_t>(v);
}

std::vector<unsigned char> SerializeHeaderV2(const CBlockHeader& header)
{
    DataStream ss;
    ss << header;
    std::vector<unsigned char> out(ss.size());
    if (!out.empty()) {
        std::memcpy(out.data(), ss.data(), ss.size());
    }
    return out;
}

uint256 Sha256dBytes(std::span<const unsigned char> bytes)
{
    return Hash(bytes);
}

uint256 GetBlockIdentity(const CBlockHeader& header)
{
    return header.GetBlockIdentity();
}

unsigned int CompactTargetForScale(size_t kind_index, const uint256& work_scale, const Params& params)
{
    Assert(kind_index < WORK_KIND_COUNT);
    arith_uint256 s{UintToArith256(work_scale)};
    if (s == 0) s = 1;
    arith_uint256 t{UintToArith256(params.powT0[kind_index])};
    t /= s;
    if (t == 0) t = 1;
    const arith_uint256 limit{UintToArith256(params.powLimitKind[kind_index])};
    if (t > limit) t = limit;
    return t.GetCompact();
}

bool CheckWorkKindHeader(const CBlockHeader& header, const Params& params)
{
    if (!header.m_header_v2) return false;
    const auto tag{DecodeWorkKindTag(header.GetCompleteVersion())};
    if (!tag) return false;
    const WorkKind* kind{LookupWorkKind(*tag)};
    if (!kind) return false;
    if (!kind->EnabledAt(header.m_height)) return false;
    if (!kind->TailRule(header)) return false;
    return kind->Check(header, header.nBits, params);
}

bool CheckWorkKindBlock(const CBlock& block, const Params& params)
{
    if (!CheckWorkKindHeader(block, params)) return false;
    const auto tag{DecodeWorkKindTag(block.GetCompleteVersion())};
    if (!tag) return false;
    return block.m_txcount == block.vtx.size();
}

} // namespace Consensus
