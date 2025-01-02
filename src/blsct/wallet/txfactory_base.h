// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/txfactory_global.h>
#include <primitives/transaction.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>

namespace blsct {
struct CreateTransactionData {
    CreateTransactionType type;
    blsct::TokenInfo tokenInfo;
    blsct::DoublePublicKey changeDestination;
    SubAddress destination;
    CAmount nAmount;
    std::string sMemo;
    TokenId token_id;
    CAmount minStake;

    Scalar tokenKey;
    std::map<std::string, std::string> nftMetadata;

    CreateTransactionData(const blsct::DoublePublicKey& changeDestination,
                          const SubAddress& destination,
                          const CAmount& nAmount,
                          const std::string& sMemo,
                          const TokenId& token_id,
                          const CreateTransactionType& type,
                          const CAmount& minStake) : type(type),
                                                     changeDestination(changeDestination),
                                                     destination(destination),
                                                     nAmount(nAmount),
                                                     sMemo(sMemo),
                                                     token_id(token_id),
                                                     minStake(minStake)
    {
    }

    CreateTransactionData(const SubAddress& destination,
                          const CAmount& nAmount,
                          const std::string& sMemo,
                          const TokenId& token_id,
                          const CreateTransactionType& type,
                          const CAmount& minStake) : type(type),
                                                     destination(destination),
                                                     nAmount(nAmount),
                                                     sMemo(sMemo),
                                                     token_id(token_id),
                                                     minStake(minStake) {}


    CreateTransactionData(const SubAddress& destination,
                          const CAmount& nAmount,
                          const std::string& sMemo) : type(NORMAL),
                                                      destination(destination),
                                                      nAmount(nAmount),
                                                      sMemo(sMemo) {}

    CreateTransactionData(const blsct::TokenInfo& tokenInfo) : type(TX_CREATE_TOKEN), tokenInfo(tokenInfo) {}

    CreateTransactionData(const blsct::TokenInfo& tokenInfo, const CAmount& mintAmount, const SubAddress& destination) : type(TX_MINT_TOKEN), tokenInfo(tokenInfo), destination(destination), nAmount(mintAmount), token_id(TokenId(tokenInfo.publicKey.GetHash())) {}

    CreateTransactionData(const blsct::TokenInfo& tokenInfo, const uint64_t& nftId, const SubAddress& destination, const std::map<std::string, std::string>& nftMetadata) : type(TX_MINT_TOKEN), tokenInfo(tokenInfo), destination(destination), token_id(TokenId(tokenInfo.publicKey.GetHash(), nftId)), nftMetadata(nftMetadata) {}
};

struct InputCandidates {
    CAmount amount;
    MclScalar gamma;
    blsct::PrivateKey spendingKey;
    TokenId token_id;
    COutPoint outpoint;
    bool is_staked_commitment;
};

class TxFactoryBase
{
protected:
    CMutableTransaction tx;
    std::map<TokenId, std::vector<UnsignedOutput>>
        vOutputs;
    std::map<TokenId, std::vector<UnsignedInput>>
        vInputs;
    std::map<TokenId, Amounts>
        nAmounts;

public:
    TxFactoryBase(){};

    // Normal transfer
    void AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id = TokenId(), const CreateTransactionType& type = NORMAL, const CAmount& minStake = 0, const bool& fSubtractFeeFromAmount = false);
    // Create Token
    void AddOutput(const Scalar& tokenKey, const blsct::TokenInfo& tokenInfo);
    // Mint Token
    void AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const CAmount& mintAmount);
    // Mint NFT
    void AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const uint64_t& nftId, const std::map<std::string, std::string>& nftMetadata);
    bool AddInput(const CAmount& amount, const MclScalar& gamma, const blsct::PrivateKey& spendingKey, const TokenId& token_id, const COutPoint& outpoint, const bool& stakedCommitment = false, const bool& rbf = false);
    std::optional<CMutableTransaction> BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake = 0, const CreateTransactionType& type = NORMAL, const bool& fSubtractedFee = false);
    static std::optional<CMutableTransaction> CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const CreateTransactionData& transactionData);
};

} // namespace blsct
