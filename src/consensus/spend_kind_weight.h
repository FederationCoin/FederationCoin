// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SPEND_KIND_WEIGHT_H
#define BITCOIN_CONSENSUS_SPEND_KIND_WEIGHT_H

#include <consensus/checked_arith.h>
#include <consensus/mldsa87_spend.h>
#include <consensus/mldsa44_spend.h>
#include <consensus/secp_spend.h>
#include <pubkey.h>
#include <script/modern_sig.h>

#include <array>
#include <cstdint>
#include <limits>
#include <optional>

namespace Consensus {

/** One single-key spend kind. A later fork adds a row. Historic rows stay. */
struct SpendKindRow {
    int valid_from;
    uint32_t spk_len;
    uint32_t pubkey_len;
    uint32_t max_sig_len;
};

/** Native SegWit is BIP 141 P2WPKH. max_sig_len is BIP66 DER plus sighash.
 *  pubkey_len is a compressed secp256k1 pubkey. Dilithium lengths are the
 *  ML-DSA constants. */
inline constexpr std::array<SpendKindRow, 3> SPEND_KIND_ROWS{{
    {/*valid_from=*/0, /*spk_len=*/22, /*pubkey_len=*/static_cast<uint32_t>(CPubKey::COMPRESSED_SIZE), /*max_sig_len=*/static_cast<uint32_t>(BIP66_DER_SIGHASH_SIZE_MAX)},
    {/*valid_from=*/0, /*spk_len=*/DILITHIUM_SINGLE_SCRIPT_SIZE, /*pubkey_len=*/static_cast<uint32_t>(MLDSA44_PUBLIC_KEY_SIZE), /*max_sig_len=*/static_cast<uint32_t>(MLDSA44_SIGNATURE_SIZE)},
    {/*valid_from=*/0, /*spk_len=*/DILITHIUM_SINGLE_SCRIPT_SIZE, /*pubkey_len=*/static_cast<uint32_t>(MLDSA87_PUBLIC_KEY_SIZE), /*max_sig_len=*/static_cast<uint32_t>(MLDSA87_SIGNATURE_SIZE)},
}};
static_assert(SPEND_KIND_ROWS[1].spk_len == DILITHIUM_SINGLE_SCRIPT_SIZE);
static_assert(SPEND_KIND_ROWS[2].spk_len == DILITHIUM_SINGLE_SCRIPT_SIZE);
static_assert(DILITHIUM_SINGLE_SCRIPT_SIZE == 36);

/** Compact-size length for n < 253 (1 byte) or n <= 0xffff (3 bytes).
 *  Larger n is outside this table. nullopt, not a wrapped length. */
inline constexpr std::optional<uint64_t> CompactSizeLength(uint64_t n)
{
    if (n < 253) return uint64_t{1};
    if (n <= 0xffff) return uint64_t{3};
    return std::nullopt;
}

/** Weight of one input and one output of this kind, empty scriptSig, two
 *  witness items (max signature, pubkey), marker and flag. Not multisig.
 *  nullopt when a length or the weight sum does not fit the formula. */
inline constexpr std::optional<uint64_t> SimplePaymentWeight(const SpendKindRow& kind)
{
    const std::optional<uint64_t> spk_compact{CompactSizeLength(kind.spk_len)};
    const std::optional<uint64_t> sig_compact{CompactSizeLength(kind.max_sig_len)};
    const std::optional<uint64_t> pub_compact{CompactSizeLength(kind.pubkey_len)};
    const std::optional<uint64_t> item_count{CompactSizeLength(2)};
    if (!spk_compact || !sig_compact || !pub_compact || !item_count) return std::nullopt;

    uint64_t script_and_value{0};
    if (!CheckedAdd(8, *spk_compact, script_and_value)) return std::nullopt;
    if (!CheckedAdd(script_and_value, kind.spk_len, script_and_value)) return std::nullopt;

    // base = 4 + 1 + 41 + 1 + (8 + compact(spk) + spk) + 4
    uint64_t base{4 + 1 + 41 + 1 + 4};
    if (!CheckedAdd(base, script_and_value, base)) return std::nullopt;

    // witness = 2 + compact(2) + compact(sig) + sig + compact(pubkey) + pubkey
    uint64_t witness{2};
    if (!CheckedAdd(witness, *item_count, witness)) return std::nullopt;
    if (!CheckedAdd(witness, *sig_compact, witness)) return std::nullopt;
    if (!CheckedAdd(witness, kind.max_sig_len, witness)) return std::nullopt;
    if (!CheckedAdd(witness, *pub_compact, witness)) return std::nullopt;
    if (!CheckedAdd(witness, kind.pubkey_len, witness)) return std::nullopt;

    if (base > std::numeric_limits<uint64_t>::max() / 4) return std::nullopt;
    uint64_t weight{base * 4};
    if (!CheckedAdd(weight, witness, weight)) return std::nullopt;
    return weight;
}

/** ceil(weight / 4) of a simple payment. nullopt when the weight is missing. */
inline constexpr std::optional<uint64_t> SimplePaymentVsize(const SpendKindRow& kind)
{
    const std::optional<uint64_t> weight{SimplePaymentWeight(kind)};
    if (!weight) return std::nullopt;
    return (*weight + 3) / 4;
}

/** Smallest simple-payment weight among kinds with valid_from <= height.
 *  nullopt when no kind is legal yet, or a row cannot be weighed. */
inline std::optional<uint64_t> SmallestSimplePaymentWeight(int height)
{
    std::optional<uint64_t> smallest;
    for (const SpendKindRow& kind : SPEND_KIND_ROWS) {
        if (kind.valid_from > height) continue;
        const std::optional<uint64_t> weight{SimplePaymentWeight(kind)};
        if (!weight) return std::nullopt;
        if (!smallest || *weight < *smallest) smallest = *weight;
    }
    return smallest;
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_SPEND_KIND_WEIGHT_H
