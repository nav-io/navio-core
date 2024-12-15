// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/tokens/info.h>

namespace blsct {
std::string TokenTypeToString(const TokenType& type)
{
    switch (type) {
    case TOKEN: {
        return "token";
    }
    case NFT: {
        return "nft";
    }
    default:
        return "unknown";
    }
}
} // namespace blsct