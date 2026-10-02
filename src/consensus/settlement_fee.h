// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_SETTLEMENT_FEE_H
#define BITCOIN_CONSENSUS_SETTLEMENT_FEE_H

#include <consensus/amount.h>

#include <cstdint>

/** Consensus minimum fee is floor(virtual bytes / this). A virtual byte is
 *  transaction weight divided by four. Changing this is a fork. */
static constexpr int64_t MIN_FEE_VSIZE_DIVISOR{12};

/** Floor of virtual bytes over MIN_FEE_VSIZE_DIVISOR. Zero when virtual_bytes
 *  is not positive. Coinbase transactions are not passed here. */
CAmount MinimumFee(int64_t virtual_bytes);

/** fee is at least MinimumFee(virtual_bytes). */
bool FeeMeetsMinimumRate(CAmount fee, int64_t virtual_bytes);

#endif // BITCOIN_CONSENSUS_SETTLEMENT_FEE_H
