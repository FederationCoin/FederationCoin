// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/mldsa87_spend.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

int FromHex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool ParseHex(const std::string& in, std::vector<unsigned char>& out)
{
    if (in.size() % 2 != 0) return false;
    out.clear();
    out.reserve(in.size() / 2);
    for (size_t i = 0; i < in.size(); i += 2) {
        const int hi{FromHex(in[i])};
        const int lo{FromHex(in[i + 1])};
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

std::string ToHex(const unsigned char* data, size_t len)
{
    static constexpr char hex[] = "0123456789abcdef";
    std::string out(len * 2, '0');
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0xf];
    }
    return out;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc == 3 && std::strcmp(argv[1], "keygen") == 0) {
        std::vector<unsigned char> seed;
        if (!ParseHex(argv[2], seed)) return 1;
        Consensus::MlDsa87Keypair key;
        if (!Consensus::MlDsa87Keygen(seed, key)) return 1;
        const uint256 program{Consensus::MlDsa87SingleKeyProgram(key.pubkey)};
        std::cout << ToHex(key.pubkey.data(), key.pubkey.size()) << ' '
                  << ToHex(key.secret.data(), key.secret.size()) << ' '
                  << ToHex(program.begin(), 32) << '\n';
        return 0;
    }
    if (argc == 4 && std::strcmp(argv[1], "sign") == 0) {
        std::vector<unsigned char> secret;
        std::vector<unsigned char> message;
        if (!ParseHex(argv[2], secret) || !ParseHex(argv[3], message)) return 1;
        if (secret.size() != Consensus::MLDSA87_SECRET_KEY_SIZE) return 1;
        Consensus::MlDsa87Keypair key;
        std::memcpy(key.secret.data(), secret.data(), secret.size());
        std::array<unsigned char, Consensus::MLDSA87_SIGNATURE_SIZE> signature{};
        if (!Consensus::MlDsa87Sign(key, message, signature)) return 1;
        std::cout << ToHex(signature.data(), signature.size()) << '\n';
        return 0;
    }
    std::cerr << "usage: mldsa87-tool keygen <seedhex>\n"
              << "       mldsa87-tool sign <secrethex> <messagehex>\n";
    return 1;
}
