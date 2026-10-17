// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa_seed.h>

#include <crypto/blake2b.h>
#include <crypto/common.h>
#include <support/cleanse.h>

#include <vector>

namespace Consensus {

bool DeriveMlDsaSeed(std::span<const unsigned char> hd_seed, MlDsaSeedKind kind, uint32_t index,
                     std::array<unsigned char, MLDSA_DERIVED_SEED_SIZE>& out)
{
    if (hd_seed.empty()) return false;
    std::vector<unsigned char> msg;
    msg.reserve(sizeof(MLDSA_SEED_TAG) - 1 + hd_seed.size() + 1 + 4);
    msg.insert(msg.end(), MLDSA_SEED_TAG, MLDSA_SEED_TAG + sizeof(MLDSA_SEED_TAG) - 1);
    msg.insert(msg.end(), hd_seed.begin(), hd_seed.end());
    msg.push_back(static_cast<unsigned char>(kind));
    unsigned char idx[4];
    WriteLE32(idx, index);
    msg.insert(msg.end(), idx, idx + 4);
    const int rc{blake2b_nokey(out.data(), out.size(), msg.data(), msg.size())};
    memory_cleanse(msg.data(), msg.size());
    return rc == 0;
}

} // namespace Consensus
