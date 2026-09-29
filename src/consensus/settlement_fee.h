// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SETTLEMENT_FEE_H
#define BITCOIN_CONSENSUS_SETTLEMENT_FEE_H

#include <consensus/amount.h>

#include <cstdint>

/** Permanent minimum fee, in tokens per virtual byte. A token is one smallest
 *  unit. A virtual byte is transaction weight divided by four. Changing this
 *  is a fork. */
static constexpr CAmount MIN_TX_FEE_RATE{3};

/** fee is at least MIN_TX_FEE_RATE times virtual bytes. virtual_bytes is
 *  transaction weight divided by four. The multiply does not wrap. */
bool FeeMeetsMinimumRate(CAmount fee, int64_t virtual_bytes);

#endif // BITCOIN_CONSENSUS_SETTLEMENT_FEE_H
