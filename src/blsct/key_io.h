// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_KEY_IO_H
#define NAVCOIN_BLSCT_KEY_IO_H

#include <blsct/bech32_mod.h>
#include <blsct/double_public_key.h>
#include <optional>
#include <string>

namespace blsct {

// ** COPIED FROM src/key_io.h **
//
// double public key after encoding to bech32_mod is 165-byte long consisting of:
// - 2-byte hrp
// - 1-byte separator '1'
// - 154-byte data
// - 8-byte checksum
constexpr size_t DOUBLE_PUBKEY_ENC_SIZE = 3 + 1 + bech32_mod::DOUBLE_PUBKEY_DATA_ENC_SIZE + 8;

namespace bech32_hrp {
    const std::string Mainnet = "nav";
    const std::string Testnet = "tnv";
    const std::string Signet = "snv";
    const std::string Regtest = "rnav";
}

/** Encode DoublePublicKey to Bech32 or Bech32m string. Encoding must be one of BECH32 or BECH32M. */
std::string EncodeDoublePublicKey(
    const std::string bech32_mod_hrp,
    const bech32_mod::Encoding encoding,
    const blsct::DoublePublicKey& dpk
);

/** Decode a Bech32 or Bech32m string to a DoublePublicKey. */
std::optional<blsct::DoublePublicKey> DecodeDoublePublicKey(
    const std::string bech32_mod_hrp,
    const std::string& str
);

} // namespace blsct

#endif // NAVCOIN_BLSCT_KEY_IO_H

