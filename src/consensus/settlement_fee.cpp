// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/settlement_fee.h>

#include <consensus/amount.h>

bool FeeMeetsMinimumRate(CAmount fee, int64_t virtual_bytes)
{
    if (virtual_bytes <= 0) return true;
    if (virtual_bytes > MAX_MONEY / MIN_TX_FEE_RATE) return false;
    const CAmount required{MIN_TX_FEE_RATE * virtual_bytes};
    return fee >= required;
}
