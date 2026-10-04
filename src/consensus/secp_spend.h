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

bool CheckSecpSingleKeySpend(const uint160& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash);
bool IsSecpSingleWitness(const std::vector<std::vector<unsigned char>>& witness);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_SECP_SPEND_H
