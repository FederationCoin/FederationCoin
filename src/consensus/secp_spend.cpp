// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/secp_spend.h>

#include <hash.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <uint256.h>

#include <algorithm>

namespace Consensus {

bool IsSecpSingleWitness(const std::vector<std::vector<unsigned char>>& witness)
{
    if (witness.size() != SECP_SINGLE_WITNESS_ITEMS) return false;
    if (witness[1].size() != CPubKey::COMPRESSED_SIZE) return false;
    if (witness[0].size() < BIP66_DER_SIGHASH_SIZE_MIN || witness[0].size() > BIP66_DER_SIGHASH_SIZE_MAX) return false;
    return witness[0].back() == (SIGHASH_ALL | SIGHASH_UNIFIED);
}

bool CheckSecpSingleKeySpend(const uint160& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    if (!IsSecpSingleWitness(witness)) return false;
    if (sighash.size() != UNIFIED_SIGHASH_SIZE) return false;
    const CPubKey pubkey{Span<const unsigned char>{witness[1]}};
    if (!pubkey.IsFullyValid() || !pubkey.IsCompressed()) return false;
    if (Hash160(pubkey) != program) return false;
    if (!CheckSignatureEncoding(witness[0], SCRIPT_VERIFY_DERSIG, nullptr)) return false;

    std::vector<unsigned char> signature{witness[0].begin(), witness[0].end() - 1};
    uint256 message;
    std::copy(sighash.begin(), sighash.end(), message.begin());
    return pubkey.Verify(message, signature);
}

} // namespace Consensus
