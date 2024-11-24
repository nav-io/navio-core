// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/key_io.h>
#include <util/strencodings.h>

#include <vector>

namespace blsct {

std::string EncodeDoublePublicKey(
    const std::string bech32_mod_hrp,
    const bech32_mod::Encoding encoding,
    const blsct::DoublePublicKey& dpk
) {
    std::vector<uint8_t> dpk_v8 = dpk.GetVch();
    std::vector<uint8_t> dpk_v5;
    dpk_v5.reserve(DOUBLE_PUBKEY_ENC_SIZE);

    // ignoring the return value since this conversion always succeeds
    ConvertBits<8, 5, true>([&](uint8_t c) { dpk_v5.push_back(c); }, dpk_v8.begin(), dpk_v8.end());

    return Encode(encoding, bech32_mod_hrp, dpk_v5);
}

std::optional<blsct::DoublePublicKey> DecodeDoublePublicKey(
    const std::string bech32_mod_hrp,
    const std::string& str
) {
    const auto hrp = ToLower(str.substr(0, bech32_mod_hrp.size()));

    // str needs to be of the expected length and have the expected hrp
    if (str.size() != DOUBLE_PUBKEY_ENC_SIZE
        || hrp != bech32_mod_hrp
        || str[bech32_mod_hrp.size()] != '1'
    ) return std::nullopt;

    // decode to 5-bit based byte vector
    const auto dec = bech32_mod::Decode(str);

    // check if it has expected encoding and the data is of the expected length
    if ((dec.encoding != bech32_mod::Encoding::BECH32 && dec.encoding != bech32_mod::Encoding::BECH32M)
        || dec.data.size() != 154
    ) return std::nullopt;

    // The data part consists of two concatenated 48-byte public keys
    std::vector<uint8_t> data;
    data.reserve(blsct::DoublePublicKey::SIZE);
    if (!ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, dec.data.begin(), dec.data.end())) {
        return std::nullopt;
    }

    blsct::DoublePublicKey dpk(data);
    if (dpk.IsValid()) {
        return dpk;
    } else {
        return std::nullopt;
    }
}

} // namespace blsct
