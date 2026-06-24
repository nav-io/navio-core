// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TXFACTORY_H
#define TXFACTORY_H

#include <blsct/arith/elements.h>
#include <blsct/wallet/keyman.h>
#include <blsct/wallet/txfactory_base.h>
#include <blsct/wallet/txfactory_global.h>
#include <policy/fees.h>
#include <rpc/protocol.h>
#include <univalue.h>
#include <util/rbf.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

namespace blsct {

class TxFactory : public TxFactoryBase
{
private:
    KeyMan* km;

public:
    TxFactory(KeyMan* km) : km(km){};

    bool AddInput(wallet::CWallet* wallet, const COutPoint& outpoint, const bool& stakedCommitment = false, const bool& rbf = false) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet);
    bool AddInput(const CCoinsViewCache& cache, const COutPoint& outpoint, const bool& stakedCommitment = false, const bool& rbf = false);
    //! `nBLSCTDefaultFee` overrides the per-byte fee rate (nullopt = consensus
    //! default). `additionalFee` over-funds the fee output so an aggregation
    //! initiator can cover the combined weight of its half + fee-0 candidates.
    std::optional<CMutableTransaction> BuildTx(const std::optional<CAmount>& nBLSCTDefaultFee = std::nullopt, const CAmount& additionalFee = 0);
    static std::optional<CMutableTransaction> CreateTransaction(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, CreateTransactionData transactionData);
    static void AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const wallet::CoinFilterParams& coins_params, std::vector<InputCandidates>& inputCandidates, const CAmount& nAmountLimit) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet);
    static void AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const TokenId& token_id, const CreateTransactionType& type, std::vector<InputCandidates>& inputCandidates, const CAmount& nAmountLimit) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet);
};
} // namespace blsct

#endif // TXFACTORY_H
