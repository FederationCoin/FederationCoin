// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_WORK_KIND_H
#define BITCOIN_CONSENSUS_WORK_KIND_H

#include <consensus/params.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

class CBlockHeader;
class CBlock;

namespace Consensus {

/** Four frozen work kinds. Bits 8–9 of GetCompleteVersion(). */
enum class WorkKindTag : uint8_t {
    BLAKE2B = 0,
    SHA256D = 1,
    FP8_GYM = 2,
    POSEIDON2 = 3,
};

static constexpr unsigned WORK_KIND_COUNT{4};
static constexpr uint32_t VERSION_WORK_KIND_SHIFT{8};
static constexpr uint32_t VERSION_WORK_KIND_MASK{0x00000300};
/** Unused version bits that must stay 0. Kind is bits 8–9; bit 31 is v2.
 *  Legal extras: 12–13 (unknown/BIP320 warnings), 28 testdummy, 29 TOP_BITS, 30 unknown schema. */
static constexpr uint32_t VERSION_WORK_RESERVED_MASK{0x0FFFCC00};

/** Closed strategy. Validation looks up the tag and runs this object. */
class WorkKind
{
public:
    virtual ~WorkKind() = default;
    virtual WorkKindTag Kind() const = 0;
    virtual const char* Name() const = 0;
    /** 0 = genesis. */
    virtual int EnableHeight() const { return 0; }
    /** 0 = never. Valid at h iff h >= enable and (expire == 0 or h < expire). */
    virtual int ExpireHeight() const { return 0; }
    virtual bool EnabledAt(int height) const
    {
        if (height < EnableHeight()) return false;
        const int expire{ExpireHeight()};
        return expire == 0 || height < expire;
    }
    /** 256-bit work digest. Poseidon2 Check uses the 512-bit squeeze; this
     *  returns the high 256 bits of that U512 (big-endian). */
    virtual uint256 WorkDigest(const CBlockHeader& header) const = 0;
    /** Header-only tail. Do not read vtx. txcount vs vtx is CheckBlock. */
    virtual bool TailRule(const CBlockHeader& header) const = 0;
    /** Zero fields this kind forbids grinding. Called from CreateNewBlock. */
    virtual void PrepareTemplate(CBlockHeader& header) const = 0;
    virtual bool Check(const CBlockHeader& header, unsigned int nBits, const Params& params) const = 0;
    /** Compact T0[k]/S, floors 1 and powLimitKind[k]. */
    virtual unsigned int ExpectedNBits(const uint256& work_scale, const Params& params) const = 0;
};

const WorkKind* LookupWorkKind(WorkKindTag tag);
const WorkKind* WorkKindAt(size_t index);

/** Nullopt if not header-v2 or unused bits (10–27, 30) are set. All four tags 00..11 hit. */
std::optional<WorkKindTag> DecodeWorkKindTag(uint32_t complete_version);
void ApplyWorkKindTag(CBlockHeader& header, WorkKindTag tag);

/** 164-byte v2 serialization. Empty if not v2. */
std::vector<unsigned char> SerializeHeaderV2(const CBlockHeader& header);
uint256 Sha256dBytes(std::span<const unsigned char> bytes);

/** SHA-256d of the full 164 bytes. Blake2b identity is GetHash() instead. */
uint256 GetBlockIdentity(const CBlockHeader& header);

/** Compact T0[k]/S with floors. Index is WorkKindTag. */
unsigned int CompactTargetForScale(size_t kind_index, const uint256& work_scale, const Params& params);

bool CheckWorkKindHeader(const CBlockHeader& header, const Params& params);

/** txcount vs vtx, after parent connected. Header-only path does not call this. */
bool CheckWorkKindBlock(const CBlock& block, const Params& params);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_WORK_KIND_H
