// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CHECKED_ARITH_H
#define BITCOIN_CONSENSUS_CHECKED_ARITH_H

#include <cstdint>
#include <limits>

namespace Consensus {

/** True when a + b fits in uint64_t. On failure, sum is unchanged. */
inline constexpr bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& sum)
{
    if (a > std::numeric_limits<uint64_t>::max() - b) return false;
    sum = a + b;
    return true;
}

/** Low 64 bits of a + b. Modular 2^64. Goldilocks reduction uses wrap, not fail.
 *  Does not evaluate a overflowing uint64_t add (UBSan unsigned-integer-overflow). */
inline constexpr uint64_t WrappingAddU64(uint64_t a, uint64_t b)
{
    constexpr uint64_t max{std::numeric_limits<uint64_t>::max()};
    if (b > max - a) return b - (max - a) - 1;
    return a + b;
}

/** Low 64 bits of a - b. Modular 2^64. Same UBSan constraint as WrappingAddU64. */
inline constexpr uint64_t WrappingSubU64(uint64_t a, uint64_t b)
{
    constexpr uint64_t max{std::numeric_limits<uint64_t>::max()};
    if (b > a) return max - (b - a) + 1;
    return a - b;
}

/** True when a * b fits in uint64_t. On failure, product is unchanged.
 *  This is not the 128-bit multiply. Use Mul128 when the product is only compared. */
inline bool CheckedMul(uint64_t a, uint64_t b, uint64_t& product)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) return false;
    product = a * b;
    return true;
}

/** Floor toward zero of numerator / divisor. Divisor 0 leaves quotient unchanged and returns false. */
inline bool FloorDiv(uint64_t numerator, uint64_t divisor, uint64_t& quotient)
{
    if (divisor == 0) return false;
    quotient = numerator / divisor;
    return true;
}

/** Sum of two int64 values. False when the sum would leave int64. sum is unchanged
 *  on failure. This is addition, not a floor division. */
inline bool CheckedAddSigned(int64_t a, int64_t b, int64_t& sum)
{
    if (b > 0 && a > std::numeric_limits<int64_t>::max() - b) return false;
    if (b < 0 && a < std::numeric_limits<int64_t>::min() - b) return false;
    sum = a + b;
    return true;
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_CHECKED_ARITH_H
