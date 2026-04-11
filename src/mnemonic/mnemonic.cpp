// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mnemonic/mnemonic.h>
#include <mnemonic/wordlist.h>
#include <crypto/sha256.h>
#include <random.h>

#include <algorithm>
#include <sstream>

namespace mnemonic {

std::string Generate()
{
    std::vector<unsigned char> entropy(32);
    GetStrongRandBytes(entropy);
    return EntropyToMnemonic(entropy);
}

std::string EntropyToMnemonic(Span<const unsigned char> entropy)
{
    size_t ent_bytes = entropy.size();
    if (ent_bytes < 16 || ent_bytes > 32 || ent_bytes % 4 != 0) {
        return "";
    }

    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(entropy.data(), ent_bytes).Finalize(hash);

    std::vector<unsigned char> bits(entropy.begin(), entropy.end());
    bits.push_back(hash[0]);

    size_t ent_bits = ent_bytes * 8;
    size_t cs_bits = ent_bits / 32;
    size_t total_bits = ent_bits + cs_bits;
    size_t num_words = total_bits / 11;

    std::string result;
    for (size_t i = 0; i < num_words; i++) {
        size_t bit_offset = i * 11;
        size_t byte_idx = bit_offset / 8;
        size_t bit_idx = bit_offset % 8;

        uint32_t val = 0;
        val |= static_cast<uint32_t>(bits[byte_idx]) << 16;
        if (byte_idx + 1 < bits.size())
            val |= static_cast<uint32_t>(bits[byte_idx + 1]) << 8;
        if (byte_idx + 2 < bits.size())
            val |= static_cast<uint32_t>(bits[byte_idx + 2]);

        uint32_t index = (val >> (24 - bit_idx - 11)) & 0x7FF;

        if (i > 0) result += " ";
        result += wordlist_en[index];
    }

    return result;
}

std::optional<std::vector<unsigned char>> MnemonicToEntropy(const std::string& words_str)
{
    std::vector<std::string> words;
    std::istringstream iss(words_str);
    std::string word;
    while (iss >> word) {
        words.push_back(word);
    }

    if (words.size() != 12 && words.size() != 15 && words.size() != 18 &&
        words.size() != 21 && words.size() != 24) {
        return std::nullopt;
    }

    std::vector<uint16_t> indices;
    for (const auto& w : words) {
        auto it = std::lower_bound(wordlist_en.begin(), wordlist_en.end(), w,
            [](const char* a, const std::string& b) { return std::string(a) < b; });
        if (it == wordlist_en.end() || std::string(*it) != w) {
            return std::nullopt;
        }
        indices.push_back(static_cast<uint16_t>(std::distance(wordlist_en.begin(), it)));
    }

    size_t total_bits = words.size() * 11;
    size_t cs_bits = words.size() / 3;
    size_t ent_bits = total_bits - cs_bits;
    size_t ent_bytes = ent_bits / 8;

    std::vector<unsigned char> buf((total_bits + 7) / 8, 0);
    for (size_t i = 0; i < indices.size(); i++) {
        size_t bit_offset = i * 11;
        for (int b = 0; b < 11; b++) {
            if (indices[i] & (1 << (10 - b))) {
                size_t pos = bit_offset + b;
                buf[pos / 8] |= (1 << (7 - (pos % 8)));
            }
        }
    }

    std::vector<unsigned char> entropy(buf.begin(), buf.begin() + ent_bytes);

    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(entropy.data(), entropy.size()).Finalize(hash);

    unsigned char actual_cs = buf[ent_bytes];
    unsigned char expected_cs = hash[0];
    unsigned char mask = static_cast<unsigned char>(0xFF << (8 - cs_bits));
    if ((actual_cs & mask) != (expected_cs & mask)) {
        return std::nullopt;
    }

    return entropy;
}

bool Validate(const std::string& words)
{
    return MnemonicToEntropy(words).has_value();
}

} // namespace mnemonic