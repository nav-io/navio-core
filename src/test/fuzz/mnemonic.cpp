// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mnemonic/mnemonic.h>
#include <test/fuzz/fuzz.h>

#include <cstdint>
#include <string>
#include <vector>

FUZZ_TARGET(mnemonic)
{
    const std::string random_string(buffer.begin(), buffer.end());

    {
        const std::string result = mnemonic::EntropyToMnemonic(
            std::vector<unsigned char>(buffer.begin(), buffer.end()));
        if (!result.empty()) {
            auto decoded = mnemonic::MnemonicToEntropy(result);
            if (decoded.has_value()) {
                assert(mnemonic::Validate(result));
            }
        }
    }

    {
        auto result = mnemonic::MnemonicToEntropy(random_string);
        if (result.has_value()) {
            std::string re_encoded = mnemonic::EntropyToMnemonic(result.value());
            assert(!re_encoded.empty());
            assert(mnemonic::Validate(re_encoded));
        }
        assert(mnemonic::Validate(random_string) == result.has_value());
    }
}