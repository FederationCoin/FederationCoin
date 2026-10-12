// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa87_spend.h>

#include <crypto/mldsa_randombytes.h>

#include <cstdint>

extern "C" {
#include <crypto/mldsa87/api.h>
}

namespace Consensus {

bool MlDsa87Keygen(std::span<const unsigned char> seed, MlDsa87Keypair& out)
{
    if (seed.size() != MLDSA87_SEED_SIZE) return false;
    mldsa87_use_seed(seed.data(), seed.size());
    const int rc{PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(out.pubkey.data(), out.secret.data())};
    mldsa87_use_seed(nullptr, 0);
    return rc == 0;
}

bool MlDsa87Sign(const MlDsa87Keypair& key, std::span<const unsigned char> message, std::span<unsigned char> signature)
{
    if (signature.size() != MLDSA87_SIGNATURE_SIZE) return false;
    static constexpr char context[]{"FederationCoin"};
    size_t siglen{0};
    const int rc{PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx(signature.data(), &siglen, message.data(), message.size(), reinterpret_cast<const uint8_t*>(context), sizeof(context) - 1, key.secret.data())};
    return rc == 0 && siglen == MLDSA87_SIGNATURE_SIZE;
}

bool MlDsa87Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message)
{
    if (pubkey.size() != MLDSA87_PUBLIC_KEY_SIZE) return false;
    if (signature.size() != MLDSA87_SIGNATURE_SIZE) return false;
    static constexpr char context[]{"FederationCoin"};
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(signature.data(), signature.size(), message.data(), message.size(), reinterpret_cast<const uint8_t*>(context), sizeof(context) - 1, pubkey.data()) == 0;
}

bool MlDsa87Kind::Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> signature, std::span<const unsigned char> message)
{
    return MlDsa87Verify(pubkey, signature, message);
}

uint256 MlDsa87KeyHash(std::span<const unsigned char> pubkey)
{
    return MlDsaTaggedKeyHash<MlDsa87Kind>(pubkey);
}

uint256 MlDsa87SingleKeyProgram(std::span<const unsigned char> pubkey)
{
    return MlDsa87KeyHash(pubkey);
}

std::optional<uint256> MlDsa87PolicyProgram(uint8_t threshold, std::span<const uint256> key_hashes)
{
    return MlDsaTaggedPolicyProgram<MlDsa87Kind>(threshold, key_hashes);
}

bool CheckSingleKey87Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    return CheckSingleKeySpendOf<MlDsa87Kind>(program, witness, sighash);
}

bool CheckMultisig87Spend(const uint256& program, const std::vector<std::vector<unsigned char>>& witness, std::span<const unsigned char> sighash)
{
    return CheckMultisigSpendOf<MlDsa87Kind>(program, witness, sighash);
}

std::optional<std::vector<std::vector<unsigned char>>> MergeMlDsa87Witnesses(
    const std::vector<std::vector<std::vector<unsigned char>>>& stacks,
    std::span<const unsigned char> sighash)
{
    return MergeMlDsaWitnesses<MlDsa87Kind>(stacks, sighash);
}

MlDsa87WitnessLayout ClassifyMlDsa87Witness(const std::vector<std::vector<unsigned char>>& witness)
{
    return ClassifyMlDsaWitness<MlDsa87Kind>(witness);
}

} // namespace Consensus
