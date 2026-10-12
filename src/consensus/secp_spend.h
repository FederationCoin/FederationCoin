// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SECP_SPEND_H
#define BITCOIN_CONSENSUS_SECP_SPEND_H

#include <cstdint>
#include <span>
#include <vector>

class uint160;

namespace Consensus {

/** Native SegWit P2WPKH witness arity: signature+hashtype, compressed pubkey. */
static constexpr size_t SECP_SINGLE_WITNESS_ITEMS{2};
/** BIP66 minimum DER (8 bytes) plus one sighash byte. Same bound as
 *  IsValidSignatureEncoding. */
static constexpr size_t BIP66_DER_SIGHASH_SIZE_MIN{9};
/** BIP66 maximum DER (72 bytes) plus one sighash byte. Same bound as
 *  IsValidSignatureEncoding. */
static constexpr size_t BIP66_DER_SIGHASH_SIZE_MAX{73};
/** Unified sighash message length (Blake2b-256). Not a raw transaction. */
static constexpr size_t UNIFIED_SIGHASH_SIZE{32};

/** True iff this witness stack shape is a native SegWit single-key spend
 *  (BIP 141 P2WPKH) under our unified-sighash rule. Layout only: two items,
 *  compressed 33-byte pubkey, DER+hashtype length in
 *  [BIP66_DER_SIGHASH_SIZE_MIN, BIP66_DER_SIGHASH_SIZE_MAX], last byte
 *  SIGHASH_ALL | SIGHASH_UNIFIED. Does not prove the coins move. */
bool IsSecpSingleWitness(const std::vector<std::vector<unsigned char>>& witness);

/** Consensus yes/no for spending a v0/20 output (20-byte Hash160 of a
 *  compressed pubkey) with this witness and this 32-byte unified message.
 *  Sequence: IsSecpSingleWitness, sighash size UNIFIED_SIGHASH_SIZE, pubkey
 *  IsFullyValid and compressed, Hash160 matches program, BIP66 DER, ECDSA
 *  verify of the DER against the message. A passing shape with a wrong
 *  Hash160, a bad DER, or a bad ECDSA is still a fail. */
bool CheckSecpSingleKeySpend(const uint160& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_SECP_SPEND_H
