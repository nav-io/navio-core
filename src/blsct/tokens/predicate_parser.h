// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_TOKENS_PREDICATE_PARSER_H
#define NAVIO_BLSCT_TOKENS_PREDICATE_PARSER_H

#include <blsct/public_key.h>
#include <blsct/tokens/info.h>
#include <blsct/tokens/predicate.h>
#include <coins.h>

namespace blsct {

enum PredicateOperation : uint8_t {
    CREATE_TOKEN,
    MINT,
    NFT_MINT,
    PAY_FEE
};

struct CreateTokenPredicate {
    blsct::TokenInfo tokenInfo;

    CreateTokenPredicate(){};
    CreateTokenPredicate(const blsct::TokenInfo& tokenInfo) : tokenInfo(tokenInfo){};

    SERIALIZE_METHODS(CreateTokenPredicate, obj)
    {
        READWRITE(obj.tokenInfo);
    }

    VectorPredicate GetVch()
    {
        DataStream ss;
        ss << CREATE_TOKEN;
        ss << tokenInfo;
        return VectorPredicate(ss.data(), ss.data() + ss.size());
    }
};

struct MintTokenPredicate {
    blsct::PublicKey publicKey;
    CAmount amount;

    MintTokenPredicate(){};
    MintTokenPredicate(const blsct::PublicKey& publicKey, const CAmount& amount) : publicKey(publicKey), amount(amount){};

    SERIALIZE_METHODS(MintTokenPredicate, obj)
    {
        READWRITE(obj.publicKey, obj.amount);
    }

    VectorPredicate GetVch()
    {
        DataStream ss;
        ss << MINT;
        ss << publicKey;
        ss << amount;
        return VectorPredicate(ss.data(), ss.data() + ss.size());
    }
};

struct MintNftPredicate {
    blsct::PublicKey publicKey;
    CAmount nftId;
    std::map<std::string, std::string> nftMetadata;

    MintNftPredicate(){};
    MintNftPredicate(const blsct::PublicKey& publicKey, const CAmount& nftId, const std::map<std::string, std::string>& nftMetadata) : publicKey(publicKey), nftId(nftId), nftMetadata(nftMetadata){};

    SERIALIZE_METHODS(MintNftPredicate, obj)
    {
        READWRITE(obj.publicKey, obj.nftId, obj.nftMetadata);
    }

    VectorPredicate GetVch()
    {
        DataStream ss;
        ss << NFT_MINT;
        ss << publicKey;
        ss << nftId;
        ss << nftMetadata;
        return VectorPredicate(ss.data(), ss.data() + ss.size());
    }
};

struct PayFeePredicate {
    blsct::PublicKey publicKey;

    PayFeePredicate(){};
    PayFeePredicate(const blsct::PublicKey& publicKey) : publicKey(publicKey){};

    SERIALIZE_METHODS(PayFeePredicate, obj)
    {
        READWRITE(obj.publicKey);
    }

    VectorPredicate GetVch()
    {
        DataStream ss;
        ss << PAY_FEE;
        ss << publicKey;
        return VectorPredicate(ss.data(), ss.data() + ss.size());
    }
};

class ParsedPredicate
{
public:
    ParsedPredicate() {}
    ParsedPredicate(CreateTokenPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(MintTokenPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(MintNftPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(PayFeePredicate& predicate) : predicate_(predicate) {}

    bool IsCreateTokenPredicate() const
    {
        return std::holds_alternative<CreateTokenPredicate>(predicate_);
    }

    bool IsMintTokenPredicate() const
    {
        return std::holds_alternative<MintTokenPredicate>(predicate_);
    }

    bool IsMintNftPredicate() const
    {
        return std::holds_alternative<MintNftPredicate>(predicate_);
    }

    bool IsPayFeePredicate() const
    {
        return std::holds_alternative<PayFeePredicate>(predicate_);
    }

    blsct::PublicKey GetPublicKey() const
    {
        if (IsCreateTokenPredicate())
            return std::get<CreateTokenPredicate>(predicate_).tokenInfo.publicKey;
        else if (IsMintTokenPredicate())
            return std::get<MintTokenPredicate>(predicate_).publicKey;
        else if (IsMintNftPredicate())
            return std::get<MintNftPredicate>(predicate_).publicKey;
        else if (IsPayFeePredicate())
            return std::get<PayFeePredicate>(predicate_).publicKey;
        else
            throw std::ios_base::failure("wrong predicate type");
    }

    blsct::TokenInfo GetTokenInfo() const
    {
        if (IsCreateTokenPredicate())
            return std::get<CreateTokenPredicate>(predicate_).tokenInfo;
        else
            throw std::ios_base::failure("wrong predicate type");
    }

    CAmount GetAmount() const
    {
        if (IsMintTokenPredicate())
            return std::get<MintTokenPredicate>(predicate_).amount;
        else
            throw std::ios_base::failure("wrong predicate type");
    }

    CAmount GetNftId() const
    {
        if (IsMintNftPredicate())
            return std::get<MintNftPredicate>(predicate_).nftId;
        else
            throw std::ios_base::failure("wrong predicate type");
    }

    std::map<std::string, std::string> GetNftMetaData() const
    {
        if (IsMintNftPredicate())
            return std::get<MintNftPredicate>(predicate_).nftMetadata;
        else
            throw std::ios_base::failure("wrong predicate type");
    }

private:
    std::variant<CreateTokenPredicate, MintTokenPredicate, MintNftPredicate, PayFeePredicate>
        predicate_;
};

ParsedPredicate ParsePredicate(const VectorPredicate& vch);
std::string PredicateToString(const VectorPredicate& vch);
bool ExecutePredicate(const ParsedPredicate& predicate, CCoinsViewCache& view, const bool& fDisconnect = false);
bool ExecutePredicate(const VectorPredicate& vch, CCoinsViewCache& view, const bool& fDisconnect = false);


} // namespace blsct

#endif // NAVIO_BLSCT_TOKENS_PREDICATE_PARSER_H