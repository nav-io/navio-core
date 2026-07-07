// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_TOKENS_PREDICATE_PARSER_H
#define NAVIO_BLSCT_TOKENS_PREDICATE_PARSER_H

#include <blsct/bridge/predicates.h>
#include <blsct/public_key.h>
#include <blsct/tokens/info.h>
#include <blsct/tokens/predicate.h>

#include <variant>

namespace blsct {
enum PredicateOperation : uint8_t {
    CREATE_TOKEN,
    MINT,
    NFT_MINT,
    PAY_FEE,
    DATA,
    // NBP bridge operations (navio-bridge-protocol DESIGN.md §12).
    NBP_GUARDIAN_REGISTER,
    NBP_GUARDIAN_EXIT,
    NBP_GUARDIAN_WITHDRAW,
    NBP_GUARDIAN_SLASH,
    NBP_BRIDGE_MINT,
    NBP_BRIDGE_BURN,
    NBP_BRIDGE_CHALLENGE,
    NBP_BRIDGE_RESOLVE
};

struct CreateTokenPredicate {
    blsct::TokenInfo tokenInfo;

    CreateTokenPredicate()= default;
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

struct DataPredicate {
    std::vector<unsigned char> data;

    DataPredicate()= default;
    DataPredicate(const std::vector<unsigned char>& dataIn) : data(dataIn){};
    DataPredicate(const uint256& dataIn) : data(std::vector<unsigned char>(dataIn.begin(), dataIn.end())){};
    DataPredicate(const uint64_t& dataIn) : data(std::vector<unsigned char>(sizeof(dataIn)))
    {
        DataStream ss;
        ss << dataIn;
        std::memcpy(data.data(), ss.data(), ss.size());
    };

    SERIALIZE_METHODS(DataPredicate, obj)
    {
        READWRITE(obj.data);
    }

    VectorPredicate GetVch()
    {
        DataStream ss;
        ss << DATA;
        ss << data;
        return VectorPredicate(ss.data(), ss.data() + ss.size());
    }
};

struct MintTokenPredicate {
    blsct::PublicKey publicKey;
    CAmount amount;

    MintTokenPredicate()= default;
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
    uint64_t nftId;
    std::map<std::string, std::string> nftMetadata;

    MintNftPredicate()= default;
    MintNftPredicate(const blsct::PublicKey& publicKey, const uint64_t& nftId, const std::map<std::string, std::string>& nftMetadata) : publicKey(publicKey), nftId(nftId), nftMetadata(nftMetadata){};

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

    PayFeePredicate()= default;
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
    ParsedPredicate() = default;
    ParsedPredicate(CreateTokenPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(MintTokenPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(MintNftPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(PayFeePredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(DataPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(nbp::GuardianRegisterPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(nbp::GuardianExitPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(nbp::GuardianWithdrawPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(nbp::GuardianSlashPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(nbp::BridgeMintPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(nbp::BridgeBurnPredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(nbp::BridgeChallengePredicate& predicate) : predicate_(predicate) {}
    ParsedPredicate(nbp::BridgeResolvePredicate& predicate) : predicate_(predicate) {}

    //! Generic access to the NBP payload types.
    template <typename T>
    bool Is() const
    {
        return std::holds_alternative<T>(predicate_);
    }

    template <typename T>
    const T& Get() const
    {
        if (!Is<T>()) throw std::ios_base::failure("wrong predicate type");
        return std::get<T>(predicate_);
    }

    bool IsNbpPredicate() const
    {
        return Is<nbp::GuardianRegisterPredicate>() || Is<nbp::GuardianExitPredicate>() ||
               Is<nbp::GuardianWithdrawPredicate>() || Is<nbp::GuardianSlashPredicate>() ||
               Is<nbp::BridgeMintPredicate>() || Is<nbp::BridgeBurnPredicate>() ||
               Is<nbp::BridgeChallengePredicate>() || Is<nbp::BridgeResolvePredicate>();
    }

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

    bool IsDataPredicate() const
    {
        return std::holds_alternative<DataPredicate>(predicate_);
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

    uint64_t GetNftId() const
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
    std::variant<CreateTokenPredicate, MintTokenPredicate, MintNftPredicate, PayFeePredicate, DataPredicate,
                 nbp::GuardianRegisterPredicate, nbp::GuardianExitPredicate, nbp::GuardianWithdrawPredicate,
                 nbp::GuardianSlashPredicate, nbp::BridgeMintPredicate, nbp::BridgeBurnPredicate,
                 nbp::BridgeChallengePredicate, nbp::BridgeResolvePredicate>
        predicate_;
};

//! Serialize an NBP predicate payload as `op-byte ‖ fields` (same wire
//! format as the existing token predicates' GetVch()).
template <typename T>
VectorPredicate NbpPredicateToVch(PredicateOperation op, const T& payload)
{
    DataStream ss;
    ss << op;
    ss << payload;
    return VectorPredicate(ss.data(), ss.data() + ss.size());
}

ParsedPredicate ParsePredicate(const VectorPredicate& vch);
std::string PredicateToString(const VectorPredicate& vch);
} // namespace blsct

#endif // NAVIO_BLSCT_TOKENS_PREDICATE_PARSER_H