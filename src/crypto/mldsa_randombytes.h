// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_MLDSA_RANDOMBYTES_H
#define BITCOIN_CRYPTO_MLDSA_RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

/** Federation seeded PQCLEAN_randombytes. Not PQClean. Keygen is
 *  deterministic from a 32-byte seed; signing RNG is all-zero after
 *  the seed is consumed. 87 forwards to 44. */
#ifdef __cplusplus
extern "C" {
#endif

void mldsa44_use_seed(const uint8_t* seed, size_t len);
void mldsa87_use_seed(const uint8_t* seed, size_t len);

#ifdef __cplusplus
}
#endif

#endif // BITCOIN_CRYPTO_MLDSA_RANDOMBYTES_H
