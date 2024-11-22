// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_TOKENS_INFO_H
#define NAVIO_BLSCT_TOKENS_INFO_H

#include <blsct/public_key.h>
#include <consensus/amount.h>
#include <tinyformat.h>
#include <util/moneystr.h>

namespace blsct {
enum TokenType : unsigned char {
    TOKEN = 0,
    NFT = 1
};

std::string TokenTypeToString(const TokenType& type);

class TokenInfo
{
public:
    TokenType type;
    blsct::PublicKey publicKey;
    std::map<std::string, std::string> mapMetadata;
    CAmount nTotalSupply;

    TokenInfo(const TokenType& type, const blsct::PublicKey& publicKey, const std::map<std::string, std::string>& mapMetadata,
              const CAmount& nTotalSupply) : type(type), publicKey(publicKey), mapMetadata(mapMetadata), nTotalSupply(nTotalSupply){};
    TokenInfo(){};

    SERIALIZE_METHODS(TokenInfo, obj) { READWRITE(Using<CustomUintFormatter<1>>(obj.type), obj.publicKey, obj.mapMetadata, obj.nTotalSupply); };

    std::string ToString() const
    {
        std::string ret = strprintf("type=%s publicKey=%s", TokenTypeToString(type), publicKey.ToString());
        for (auto& it : mapMetadata) {
            ret += strprintf(" %s=%s", it.first, it.second);
        }
        ret += strprintf(" nTotalSupply=%s", FormatMoney(nTotalSupply));
        return ret;
    }
};

class TokenEntry
{
public:
    TokenInfo info;
    CAmount nSupply;
    std::map<CAmount, std::map<std::string, std::string>> mapMintedNft;

    TokenEntry(){};
    TokenEntry(const TokenInfo& info,
               const CAmount& nSupply = 0) : info(info), nSupply(nSupply){};
    TokenEntry(const TokenInfo& info,
               const std::map<CAmount, std::map<std::string, std::string>>& mapMintedNft) : info(info), mapMintedNft(mapMintedNft){};

    bool Mint(const CAmount& amount)
    {
        if (amount + nSupply > info.nTotalSupply || amount + nSupply < 0)
            return false;
        nSupply += amount;
        return true;
    };

    SERIALIZE_METHODS(TokenEntry, obj)
    {
        READWRITE(obj.info);
        if (obj.info.type == TOKEN)
            READWRITE(obj.nSupply);
        else if (obj.info.type == NFT)
            READWRITE(obj.mapMintedNft);
    };
};
} // namespace blsct

#endif // NAVIO_BLSCT_TOKENS_INFO_H