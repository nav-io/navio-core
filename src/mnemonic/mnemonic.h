// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_MNEMONIC_MNEMONIC_H
#define NAVIO_MNEMONIC_MNEMONIC_H

#include <optional>
#include <span.h>
#include <string>
#include <vector>

// FIXME: Audit the usage of strings for the mnemonic value: Should maybe use
// the secured bytes or secure string variants for passing it around internally

namespace mnemonic {

// Generate 24-word mnemonic from OS entropy (256-bit)
std::string Generate();

// Convert raw entropy -> mnemonic sentence
// Entropy must be 16, 20, 24, 28, or 32 bytes (128-256 bits, multiple of 32)
std::string EntropyToMnemonic(Span<const unsigned char> entropy);

// Convert mnemonic sentence -> raw entropy (validates checksum)
// Returns std::nullopt if mnemonic is invalid (bad word, bad checksum, bad length)
std::optional<std::vector<unsigned char>> MnemonicToEntropy(const std::string& words);

// Validate mnemonic (word count, word membership, checksum)
bool Validate(const std::string& words);

} // namespace mnemonic

#endif // NAVIO_MNEMONIC_MNEMONIC_H
