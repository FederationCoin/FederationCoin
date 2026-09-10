// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/chain_encoding.h>

#include <addresstype.h>
#include <base58.h>
#include <bech32.h>
#include <key.h>
#include <key_io.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <vector>

static bool IsKeyTokenChar(unsigned char c)
{
    // Base58 plus '0' (Bech32 data can contain 0; Base58 cannot).
    static constexpr std::string_view alphabet{"0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"};
    return alphabet.find(c) != std::string_view::npos;
}

static std::string RecodeExtKey(const std::string& encoded)
{
    std::vector<unsigned char> data;
    if (!DecodeBase58Check(encoded, data, BIP32_EXTKEY_WITH_VERSION_SIZE)) return encoded;
    if (data.size() != BIP32_EXTKEY_WITH_VERSION_SIZE) return encoded;
    const unsigned char* payload = data.data() + 4;
    if (payload[41] == 0x00) {
        CExtKey key;
        key.Decode(payload);
        if (!key.key.IsValid()) return encoded;
        return EncodeExtKey(key);
    }
    CExtPubKey key;
    key.Decode(payload);
    if (!key.pubkey.IsValid()) return encoded;
    return EncodeExtPubKey(key);
}

static std::string RecodeSecret(const std::string& encoded)
{
    std::vector<unsigned char> data;
    if (!DecodeBase58Check(encoded, data, 34)) return encoded;
    if (!(data.size() == 33 || (data.size() == 34 && data.back() == 1))) return encoded;
    CKey key;
    key.Set(data.begin() + 1, data.begin() + 33, data.size() == 34);
    if (!key.IsValid()) return encoded;
    return EncodeSecret(key);
}

static std::string RecodeBase58Address(const std::string& encoded)
{
    std::vector<unsigned char> data;
    if (!DecodeBase58Check(encoded, data, 21) || data.size() != 21) return encoded;
    const unsigned char version = data[0];
    uint160 hash;
    std::copy(data.begin() + 1, data.end(), hash.begin());
    // Bitcoin: 0/111 P2PKH, 5/196 P2SH. FederationCoin: 36/95 P2PKH, 16/197 P2SH.
    CTxDestination dest;
    if (version == 5 || version == 196 || version == 16 || version == 197) {
        dest = ScriptHash(hash);
    } else {
        dest = PKHash(hash);
    }
    const std::string out = EncodeDestination(dest);
    return out.empty() ? encoded : out;
}

static std::string RecodeBech32Address(const std::string& encoded)
{
    const auto dec = bech32::Decode(ToLower(encoded));
    if (dec.encoding == bech32::Encoding::INVALID || dec.data.empty()) return encoded;
    const int version = dec.data[0];
    std::vector<unsigned char> program;
    program.reserve(((dec.data.size() - 1) * 5) / 8);
    if (!ConvertBits<5, 8, false>([&](unsigned char c) { program.push_back(c); }, dec.data.begin() + 1, dec.data.end())) {
        return encoded;
    }
    CTxDestination dest;
    if (version == 0) {
        if (program.size() == 20) {
            WitnessV0KeyHash id;
            std::copy(program.begin(), program.end(), id.begin());
            dest = id;
        } else if (program.size() == 32) {
            WitnessV0ScriptHash id;
            std::copy(program.begin(), program.end(), id.begin());
            dest = id;
        } else {
            return encoded;
        }
    } else if (version == 1 && program.size() == WITNESS_V1_TAPROOT_SIZE) {
        WitnessV1Taproot tap;
        std::copy(program.begin(), program.end(), tap.begin());
        dest = tap;
    } else {
        dest = WitnessUnknown{version, program};
    }
    const std::string out = EncodeDestination(dest);
    return out.empty() ? encoded : out;
}

std::string RecodeKeyOrAddressForActiveChain(const std::string& encoded)
{
    if (encoded.empty()) return encoded;
    // Hex pubkeys, fingerprints, and derivation indexes must not be treated as addresses.
    if (encoded.size() >= 100 && encoded.size() <= 120) {
        std::string recoded = RecodeExtKey(encoded);
        if (recoded != encoded) return recoded;
    }
    if (encoded.size() == 51 || encoded.size() == 52) {
        std::string recoded = RecodeSecret(encoded);
        if (recoded != encoded) return recoded;
    }
    const std::string lower = ToLower(encoded);
    if (lower.find('1') != std::string::npos &&
        (lower.starts_with("bc1") || lower.starts_with("tb1") || lower.starts_with("bcrt1") ||
         lower.starts_with("fcn1") || lower.starts_with("tfcn1") || lower.starts_with("fcnrt1"))) {
        std::string recoded = RecodeBech32Address(encoded);
        if (recoded != encoded) return recoded;
    }
    if (encoded.size() >= 26 && encoded.size() <= 35) {
        std::string recoded = RecodeBase58Address(encoded);
        if (recoded != encoded) return recoded;
    }
    return encoded;
}

static std::string RecodeDescriptorTokens(const std::string& desc)
{
    std::string out;
    out.reserve(desc.size());
    for (size_t i = 0; i < desc.size();) {
        unsigned char c = static_cast<unsigned char>(desc[i]);
        if (!IsKeyTokenChar(c)) {
            out.push_back(desc[i]);
            ++i;
            continue;
        }
        size_t j = i;
        while (j < desc.size() && IsKeyTokenChar(static_cast<unsigned char>(desc[j]))) {
            ++j;
        }
        out += RecodeKeyOrAddressForActiveChain(desc.substr(i, j - i));
        i = j;
    }
    return out;
}

std::string RecodeDescriptorForActiveChain(std::string desc)
{
    std::string checksum_suffix;
    std::string body = desc;
    if (const auto pos = desc.find('#'); pos != std::string::npos) {
        checksum_suffix = desc.substr(pos); // includes '#'
        body.resize(pos);
    }
    std::string out = RecodeDescriptorTokens(body);
    if (checksum_suffix.size() == 9) {
        const std::string orig_cs = checksum_suffix.substr(1);
        const std::string orig_computed = GetDescriptorChecksum(body);
        if (!orig_computed.empty() && orig_computed == orig_cs) {
            const std::string neu = GetDescriptorChecksum(out);
            if (!neu.empty()) return out + "#" + neu;
        }
        // Invalid original checksum: keep it so Parse still reports a checksum error.
        return out + checksum_suffix;
    }
    return out + checksum_suffix;
}
