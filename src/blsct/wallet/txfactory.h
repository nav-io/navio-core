// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TXFACTORY_H
#define TXFACTORY_H

#include <blsct/arith/elements.h>
#include <blsct/wallet/keyman.h>
#include <blsct/wallet/txfactory_global.h>
#include <policy/fees.h>
#include <util/rbf.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>

namespace blsct {

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

    void AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id = TokenId(), const CreateTransactionType& type = NORMAL, const CAmount& minStake = 0, const bool& fSubtractFeeFromAmount = false);
    bool AddInput(const CAmount& amount, const MclScalar& gamma, const blsct::PrivateKey& spendingKey, const TokenId& token_id, const COutPoint& outpoint, const bool& rbf = false);
    std::optional<CMutableTransaction>
    BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake = 0, const CreateTransactionType& type = NORMAL, const bool& fSubtractedFee = false);
    static std::optional<CMutableTransaction>
    CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const blsct::DoublePublicKey& changeDestination, const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id = TokenId(), const CreateTransactionType& type = NORMAL, const CAmount& minStake = 0);
    static void AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const wallet::CoinFilterParams& coins_params, std::vector<InputCandidates>& inputCandidates) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet);
    static void AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const TokenId& token_id, const CreateTransactionType& type, std::vector<InputCandidates>& inputCandidates) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet);
};

class TxFactory : public TxFactoryBase
{
private:
    KeyMan* km;

public:
    TxFactory(KeyMan* km) : km(km){};

    bool AddInput(wallet::CWallet* wallet, const COutPoint& outpoint, const bool& rbf = false) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet);
    bool AddInput(const CCoinsViewCache& cache, const COutPoint& outpoint, const bool& rbf = false);
    std::optional<CMutableTransaction> BuildTx();
    static std::optional<CMutableTransaction> CreateTransaction(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id = TokenId(), const CreateTransactionType& type = NORMAL, const CAmount& minStake = 0);
};
} // namespace blsct

#endif // TXFACTORY_H