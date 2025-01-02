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

    vInputs[coin.out.tokenId].push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), recoveredInfo.amounts[0].amount, recoveredInfo.amounts[0].gamma, km->GetSpendingKeyForOutput(coin.out), stakedCommitment});

    if (nAmounts.count(coin.out.tokenId) == 0)
        nAmounts[coin.out.tokenId] = {0, 0, 0};

    nAmounts[coin.out.tokenId].nFromInputs += recoveredInfo.amounts[0].amount;

    return true;
}

bool TxFactory::AddInput(wallet::CWallet* wallet, const COutPoint& outpoint, const bool& stakedCommitment, const bool& rbf)
{
    AssertLockHeld(wallet->cs_wallet);

    auto tx = wallet->GetWalletTx(outpoint.hash);

    if (tx == nullptr)
        return false;

    auto out = tx->tx->vout[outpoint.n];

    if (vInputs.count(out.tokenId) == 0)
        vInputs[out.tokenId] = std::vector<UnsignedInput>();

    auto recoveredInfo = tx->GetBLSCTRecoveryData(outpoint.n);

    vInputs[out.tokenId].push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), recoveredInfo.amount, recoveredInfo.gamma, km->GetSpendingKeyForOutput(out), stakedCommitment});

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

    TxFactory::AddAvailableCoins(wallet, blsct_km, transactionData.token_id, transactionData.type, inputCandidates);

    auto changeType = transactionData.type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE ? STAKING_ACCOUNT : CHANGE_ACCOUNT;

    transactionData.changeDestination = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(changeType).value());

    if (transactionData.type == TX_CREATE_TOKEN || transactionData.type == TX_MINT_TOKEN) {
        transactionData.tokenKey = blsct_km->GetTokenKey((HashWriter{} << transactionData.tokenInfo.mapMetadata << transactionData.tokenInfo.nTotalSupply).GetHash()).GetScalar();
    }

    return TxFactoryBase::CreateTransaction(inputCandidates, transactionData);
}

void TxFactory::AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const wallet::CoinFilterParams& coins_params, std::vector<InputCandidates>& inputCandidates)
{
    AssertLockHeld(wallet->cs_wallet);
    AvailableCoins(*wallet, nullptr, std::nullopt, coins_params).All();

    for (const wallet::COutput& output : AvailableCoins(*wallet, nullptr, std::nullopt, coins_params).All()) {
        auto tx = wallet->GetWalletTx(output.outpoint.hash);

        if (tx == nullptr)
            continue;

        auto out = tx->tx->vout[output.outpoint.n];

        auto recoveredInfo = tx->GetBLSCTRecoveryData(output.outpoint.n);
        auto value = out.HasBLSCTRangeProof() ? recoveredInfo.amount : out.nValue;

        inputCandidates.push_back({value, recoveredInfo.gamma, blsct_km->GetSpendingKeyForOutput(out), out.tokenId, COutPoint(output.outpoint.hash, output.outpoint.n), out.IsStakedCommitment()});
    }
}

void TxFactory::AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const TokenId& token_id, const CreateTransactionType& type, std::vector<InputCandidates>& inputCandidates)
{
    AssertLockHeld(wallet->cs_wallet);

    wallet::CoinFilterParams coins_params;
    coins_params.min_amount = 0;
    coins_params.only_blsct = true;
    coins_params.token_id = token_id;

    AddAvailableCoins(wallet, blsct_km, coins_params, inputCandidates);

    if (type == CreateTransactionType::STAKED_COMMITMENT || type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE) {
        coins_params.include_staked_commitment = true;
        AddAvailableCoins(wallet, blsct_km, coins_params, inputCandidates);
    }

    if ((type == CreateTransactionType::NORMAL && !token_id.IsNull()) || type == CreateTransactionType::TX_MINT_TOKEN) {
        coins_params.token_id.SetNull();
        AddAvailableCoins(wallet, blsct_km, coins_params, inputCandidates);
    }
}

} // namespace blsct
