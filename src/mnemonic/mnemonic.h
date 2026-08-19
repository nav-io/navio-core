// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_MNEMONIC_MNEMONIC_H
#define NAVIO_MNEMONIC_MNEMONIC_H

#include <cstdint>
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

// Validate mnemonic (word count, word membership, checksum).
// Accepts standard BIP-39 lengths and the 26-word birthday variant.
bool Validate(const std::string& words);

// ---------------------------------------------------------------------------
// Navio birthday mnemonic v1
//
// A standard BIP-39 24-word mnemonic followed by two extra words (26 total)
// encoding the wallet's creation time ("birthday"), so a restore knows where
// to start scanning:
//
//   word 25: index w = weeks elapsed since BIRTHDAY_MNEMONIC_EPOCH
//            (2026-01-01 00:00 UTC). 11 bits cover ~39 years.
//   word 26: first 11 bits of
//            HMAC-SHA256(key=entropy, msg="navio-birthday" || w as uint16 BE)
//            binding the birthday to this seed and catching typos.
//
// Key derivation uses ONLY the first 24 words, so the derived wallet is
// identical to a plain 24-word restore and the extra words can always be
// dropped. The same format is implemented in navio-electrum and navio-sdk.
// ---------------------------------------------------------------------------

inline constexpr int64_t BIRTHDAY_MNEMONIC_EPOCH{1767225600}; // 2026-01-01 UTC
inline constexpr int64_t BIRTHDAY_MNEMONIC_WEEK{7 * 24 * 3600};

struct DecodedMnemonic {
    std::vector<unsigned char> entropy;
    std::optional<int64_t> birthday; // unix time (week floor), if encoded
};

// Append the two birthday words to a 24-word mnemonic. Returns "" if the
// mnemonic is not a valid 24-word phrase or the time is out of range.
std::string MnemonicWithBirthday(const std::string& words24, int64_t time);

// Generate a 26-word birthday mnemonic from OS entropy for creation time
// `time` (typically GetTime()).
std::string GenerateWithBirthday(int64_t time);

// Decode a standard BIP-39 mnemonic or the 26-word birthday variant.
// Returns std::nullopt if invalid (bad word, checksum, or check word).
std::optional<DecodedMnemonic> DecodeMnemonic(const std::string& words);

} // namespace mnemonic

#endif // NAVIO_MNEMONIC_MNEMONIC_H
