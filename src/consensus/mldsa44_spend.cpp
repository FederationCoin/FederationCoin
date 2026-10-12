// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa44_spend.h>

#include <crypto/mldsa_randombytes.h>

#include <cstdint>

extern "C" {
#include <crypto/mldsa44/api.h>
}

namespace Consensus {

bool MlDsa44Keygen(std::span<const unsigned char> seed, MlDsa44Keypair& out)
{
    if (seed.size() != MLDSA44_SEED_SIZE) return false;
    mldsa44_use_seed(seed.data(), seed.size());
    const int rc{PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(out.pubkey.data(), out.secret.data())};
    mldsa44_use_seed(nullptr, 0);
    return rc == 0;
}

bool MlDsa44Sign(const MlDsa44Keypair& key, std::span<const unsigned char> message, std::span<unsigned char> signature)
{
    if (signature.size() != MLDSA44_SIGNATURE_SIZE) return false;
    static constexpr char context[]{"FederationCoin"};
    size_t siglen{0};
    const int rc{PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(signature.data(), &siglen, message.data(), message.size(), reinterpret_cast<const uint8_t*>(context), sizeof(context) - 1, key.secret.data())};
    return rc == 0 && siglen == MLDSA44_SIGNATURE_SIZE;
}

bool MlDsa44Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message)
{
    if (pubkey.size() != MLDSA44_PUBLIC_KEY_SIZE) return false;
    if (signature.size() != MLDSA44_SIGNATURE_SIZE) return false;
    static constexpr char context[]{"FederationCoin"};
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(signature.data(), signature.size(), message.data(), message.size(), reinterpret_cast<const uint8_t*>(context), sizeof(context) - 1, pubkey.data()) == 0;
}

bool MlDsa44Kind::Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message)
{
    return MlDsa44Verify(pubkey, signature, message);
}

uint256 MlDsa44KeyHash(std::span<const unsigned char> pubkey)
{
    return MlDsaTaggedKeyHash<MlDsa44Kind>(pubkey);
}

uint256 MlDsa44SingleKeyProgram(std::span<const unsigned char> pubkey)
{
    return MlDsa44KeyHash(pubkey);
}

std::optional<uint256> MlDsa44PolicyProgram(uint8_t threshold, std::span<const uint256> key_hashes)
{
    return MlDsaTaggedPolicyProgram<MlDsa44Kind>(threshold, key_hashes);
}

bool CheckSingleKey44Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    return CheckSingleKeySpendOf<MlDsa44Kind>(program, witness, sighash);
}

bool CheckMultisig44Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    return CheckMultisigSpendOf<MlDsa44Kind>(program, witness, sighash);
}

std::optional<std::vector<std::vector<unsigned char>>> MergeMlDsa44Witnesses(
    const std::vector<std::vector<std::vector<unsigned char>>>& stacks,
    std::span<const unsigned char> sighash)
{
    return MergeMlDsaWitnesses<MlDsa44Kind>(stacks, sighash);
}

MlDsa44WitnessLayout ClassifyMlDsa44Witness(const std::vector<std::vector<unsigned char>>& witness)
{
    return ClassifyMlDsaWitness<MlDsa44Kind>(witness);
}

} // namespace Consensus
