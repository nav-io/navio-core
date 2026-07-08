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

// Convert mnemonic sentence + optional passphrase -> 64-byte BIP-39 seed
// (PBKDF2-HMAC-SHA512, 2048 iterations, salt = "mnemonic" + passphrase).
// Inter-word whitespace is normalized to single spaces before derivation.
// No NFKD normalization is applied: the English wordlist is ASCII-safe, but
// passphrases should be ASCII to stay interoperable with other BIP-39 wallets.
// Does not validate the mnemonic; use Validate() for that.
std::vector<unsigned char> MnemonicToSeed(const std::string& words, const std::string& passphrase = "");

// Validate mnemonic (word count, word membership, checksum)
bool Validate(const std::string& words);

} // namespace mnemonic

#endif // NAVIO_MNEMONIC_MNEMONIC_H
