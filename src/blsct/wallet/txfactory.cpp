// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/tokens/predicate_parser.h>
#include <blsct/wallet/txfactory.h>

using T = Mcl;
using Point = T::Point;
using Points = Elements<Point>;
using Scalar = T::Scalar;
using Scalars = Elements<Scalar>;

namespace blsct {

bool TxFactory::AddInput(const CCoinsViewCache& cache, const COutPoint& outpoint, const bool& stakedCommitment, const bool& rbf)
{
    Coin coin;
    if (!cache.GetCoin(outpoint, coin))
        return false;

    auto recoveredInfo = km->RecoverOutputs(std::vector<CTxOut>{coin.out});

    if (!recoveredInfo.is_completed)
        return false;

    if (vInputs.count(coin.out.tokenId) == 0)
        vInputs[coin.out.tokenId] = std::vector<UnsignedInput>();

    try {
        blsct::PrivateKey spending_key;
        if (!km->GetSpendingKeyForOutputWithCache(coin.out, spending_key)) {
            return false;
        }
        vInputs[coin.out.tokenId].push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), recoveredInfo.amounts[0].amount, recoveredInfo.amounts[0].gamma, spending_key, stakedCommitment});
    } catch (const std::exception& e) {
        LogPrintf("Error adding input: %s\n", e.what());
        return false;
    }

    if (nAmounts.count(coin.out.tokenId) == 0)
        nAmounts[coin.out.tokenId] = {0, 0, 0};

    nAmounts[coin.out.tokenId].nFromInputs += recoveredInfo.amounts[0].amount;

    return true;
}

bool TxFactory::AddInput(wallet::CWallet* wallet, const COutPoint& outpoint, const bool& stakedCommitment, const bool& rbf)
{
    AssertLockHeld(wallet->cs_wallet);

    CTxOut out;
    range_proof::RecoveredData<Mcl> recoveredInfo;

    if (wallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE)) {
        auto wout = wallet->GetWalletOutput(outpoint);

        if (wout == nullptr)
            return false;

        out = *(wout->out);

        recoveredInfo = wout->blsctRecoveryData;
    } else {
        auto tx = wallet->GetWalletTx(outpoint.hash);

        if (tx == nullptr)
            return false;

        out = tx->tx->vout[outpoint.n];

        recoveredInfo = tx->GetBLSCTRecoveryData(outpoint.n);
    }

    if (vInputs.count(out.tokenId) == 0)
        vInputs[out.tokenId] = std::vector<UnsignedInput>();

    try {
        blsct::PrivateKey spending_key;
        if (!km->GetSpendingKeyForOutputWithCache(out, spending_key)) {
            return false;
        }
        vInputs[out.tokenId]
            .push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), recoveredInfo.amount, recoveredInfo.gamma, spending_key, stakedCommitment});
    } catch (const std::exception& e) {
        LogPrintf("Error adding input: %s\n", e.what());
        return false;
    }

    if (nAmounts.count(out.tokenId) == 0)
        nAmounts[out.tokenId] = {0, 0, 0};

    nAmounts[out.tokenId].nFromInputs += recoveredInfo.amount;

    return true;
}

std::optional<CMutableTransaction>
TxFactory::BuildTx()
{
    return TxFactoryBase::BuildTx(std::get<blsct::DoublePublicKey>(km->GetNewDestination(-1).value()));
}

std::optional<CMutableTransaction> TxFactory::CreateTransaction(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, CreateTransactionData transactionData)
{
    LOCK(wallet->cs_wallet);

    std::vector<InputCandidates> inputCandidates;

    TxFactory::AddAvailableCoins(wallet, blsct_km, transactionData.token_id, transactionData.type, inputCandidates, transactionData.nAmount);

    auto changeType = transactionData.type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE ? STAKING_ACCOUNT : CHANGE_ACCOUNT;

    transactionData.changeDestination = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(changeType).value());

    if (transactionData.type == TX_CREATE_TOKEN || transactionData.type == TX_MINT_TOKEN) {
        transactionData.tokenKey = blsct_km->GetTokenKey((HashWriter{} << transactionData.tokenInfo.mapMetadata << transactionData.tokenInfo.nTotalSupply).GetHash()).GetScalar();
    }

    return TxFactoryBase::CreateTransaction(inputCandidates, transactionData);
}

void TxFactory::AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const wallet::CoinFilterParams& coins_params, std::vector<InputCandidates>& inputCandidates, const CAmount& nAmountLimit)
{
    AssertLockHeld(wallet->cs_wallet);

    CAmount nTotalAdded = 0;
    auto availableCoins = wallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE) ? AvailableBlsctCoins(*wallet, nullptr, coins_params) : AvailableCoins(*wallet, nullptr, std::nullopt, coins_params);

    for (const wallet::COutput& output : availableCoins.All()) {
        CTxOut out;
        range_proof::RecoveredData<Mcl> recoveredInfo;

        if (wallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE)) {
            auto wout = wallet->GetWalletOutput(output.outpoint);

            if (wout == nullptr)
                continue;

            out = *(wout->out);

            recoveredInfo = wout->blsctRecoveryData;
        } else {
            auto tx = wallet->GetWalletTx(output.outpoint.hash);

            if (tx == nullptr)
                continue;

            out = tx->tx->vout[output.outpoint.n];

            recoveredInfo = tx->GetBLSCTRecoveryData(output.outpoint.n);
        }
        auto value = out.HasBLSCTRangeProof() ? recoveredInfo.amount : out.nValue;

        try {
            blsct::PrivateKey spending_key;
            if (!blsct_km->GetSpendingKeyForOutputWithCache(out, spending_key)) {
                continue;
            }
            inputCandidates.push_back({value, recoveredInfo.gamma, spending_key, out.tokenId, COutPoint(output.outpoint.hash, output.outpoint.n), out.IsStakedCommitment()});
        } catch (const std::exception& e) {
            LogPrintf("Error adding input: %s\n", e.what());
            continue;
        }
        nTotalAdded += value;

        if (nTotalAdded > nAmountLimit)
            break;
    }
}

void TxFactory::AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const TokenId& token_id, const CreateTransactionType& type, std::vector<InputCandidates>& inputCandidates, const CAmount& nAmountLimit)
{
    AssertLockHeld(wallet->cs_wallet);

    wallet::CoinFilterParams coins_params;
    coins_params.min_amount = 0;
    coins_params.only_blsct = true;
    coins_params.token_id = token_id;
    coins_params.min_sum_amount = nAmountLimit + COIN;

    AddAvailableCoins(wallet, blsct_km, coins_params, inputCandidates, nAmountLimit + COIN);

    if (type == CreateTransactionType::STAKED_COMMITMENT || type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE) {
        coins_params.include_staked_commitment = true;
        coins_params.min_sum_amount = nAmountLimit;

        AddAvailableCoins(wallet, blsct_km, coins_params, inputCandidates, nAmountLimit);
    }

    if ((type == CreateTransactionType::NORMAL && !token_id.IsNull()) || type == CreateTransactionType::TX_MINT_TOKEN) {
        coins_params.token_id.SetNull();
        coins_params.min_sum_amount = COIN;
        AddAvailableCoins(wallet, blsct_km, coins_params, inputCandidates, COIN);
    }
}

} // namespace blsct
