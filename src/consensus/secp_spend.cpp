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
    if (witness.size() != 2) return false;
    if (witness[1].size() != CPubKey::COMPRESSED_SIZE) return false;
    if (witness[0].size() < 9 || witness[0].size() > 73) return false;
    return witness[0].back() == (SIGHASH_ALL | SIGHASH_UNIFIED);
}

bool CheckSecpSingleKeySpend(const uint160& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    if (!IsSecpSingleWitness(witness)) return false;
    if (sighash.size() != 32) return false;
    const CPubKey pubkey{Span<const unsigned char>{witness[1]}};
    if (!pubkey.IsFullyValid() || !pubkey.IsCompressed()) return false;
    if (Hash160(pubkey) != program) return false;

    std::vector<unsigned char> signature{witness[0].begin(), witness[0].end() - 1};
    uint256 message;
    std::copy(sighash.begin(), sighash.end(), message.begin());
    return pubkey.Verify(message, signature);
}

} // namespace Consensus
