// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_CHAIN_ENCODING_H
#define BITCOIN_TEST_UTIL_CHAIN_ENCODING_H

#include <string>

/** Re-encode a Bitcoin-era WIF, xprv/xpub, Base58, or Bech32 string with this chain's prefixes. Unchanged if it does not decode. */
std::string RecodeKeyOrAddressForActiveChain(const std::string& encoded);

/** Replace WIF / xprv / xpub / address tokens in a descriptor with this chain's encodings.
 *  A valid 8-character checksum is recomputed; an invalid or malformed checksum is kept. */
std::string RecodeDescriptorForActiveChain(std::string desc);

#endif // BITCOIN_TEST_UTIL_CHAIN_ENCODING_H
