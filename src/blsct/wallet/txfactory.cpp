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

void TxFactoryBase::AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id, const CreateTransactionType& type, const CAmount& minStake, const bool& fSubtractFeeFromAmount)
{
    UnsignedOutput out;

    out = CreateOutput(destination.GetKeys(), nAmount, sMemo, token_id, Scalar::Rand(), type, minStake);

    CAmount nFee = 0;

    if (fSubtractFeeFromAmount) {
        nFee = GetTransactioOutputWeight(out.out) * BLSCT_DEFAULT_FEE;
        out = CreateOutput(destination.GetKeys(), nAmount - nFee, sMemo, token_id, Scalar::Rand(), type, minStake);
    };

    if (nAmounts.count(token_id) == 0)
        nAmounts[token_id] = {0, 0, 0};

    nAmounts[token_id].nFromOutputs += nAmount - nFee;

    if (vOutputs.count(token_id) == 0)
        vOutputs[token_id] = std::vector<UnsignedOutput>();

    vOutputs[token_id].push_back(out);
}

// Create token
void TxFactoryBase::AddOutput(const Scalar& tokenKey, const blsct::TokenInfo& tokenInfo)
{
    UnsignedOutput out;

    out = CreateOutput(tokenKey, tokenInfo);

    TokenId token_id{tokenInfo.publicKey.GetHash()};

    if (vOutputs.count(token_id) == 0)
        vOutputs[token_id] = std::vector<UnsignedOutput>();

    vOutputs[token_id].push_back(out);
}

// Mint Token

void TxFactoryBase::AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const CAmount& mintAmount)
{
    UnsignedOutput out;

    out = CreateOutput(destination.GetKeys(), mintAmount, Scalar::Rand(), tokenKey, tokenPublicKey);

    TokenId token_id{tokenPublicKey.GetHash()};

    if (vOutputs.count(token_id) == 0)
        vOutputs[token_id] = std::vector<UnsignedOutput>();

    vOutputs[token_id].push_back(out);
}

// Mint NFT

void TxFactoryBase::AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const CAmount& nftId, const std::map<std::string, std::string>& nftMetadata)
{
    UnsignedOutput out;

    out = CreateOutput(destination.GetKeys(), Scalar::Rand(), tokenKey, tokenPublicKey, nftId, nftMetadata);

    TokenId token_id{tokenPublicKey.GetHash(), nftId};

    if (vOutputs.count(token_id) == 0)
        vOutputs[token_id] = std::vector<UnsignedOutput>();

    vOutputs[token_id].push_back(out);
}

bool TxFactoryBase::AddInput(const CAmount& amount, const MclScalar& gamma, const PrivateKey& spendingKey, const TokenId& token_id, const COutPoint& outpoint, const bool& stakedCommitment, const bool& rbf)
{
    if (vInputs.count(token_id) == 0)
        vInputs[token_id] = std::vector<UnsignedInput>();

    vInputs[token_id].push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), amount, gamma, spendingKey, stakedCommitment});

    if (nAmounts.count(token_id) == 0)
        nAmounts[token_id] = {0, 0, 0};

    nAmounts[token_id].nFromInputs += amount;

    return true;
}

std::optional<CMutableTransaction>
TxFactoryBase::BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake, const CreateTransactionType& type, const bool& fSubtractedFee)
{
    this->tx = CMutableTransaction();

    std::vector<Signature> outputSignatures;
    Scalar outputGammas;
    nAmounts[TokenId()].nFromFee = 0;

    for (auto& out_ : vOutputs) {
        for (auto& out : out_.second) {
            this->tx.vout.push_back(out.out);
            auto outHash = out.out.GetHash();

            if (out.out.HasBLSCTRangeProof()) {
                outputGammas = outputGammas - out.gamma;
            }
            if (out.out.HasBLSCTKeys()) {
                outputSignatures.push_back(PrivateKey(out.blindingKey).Sign(outHash));
            }

            if (out.type == TX_CREATE_TOKEN || out.type == TX_MINT_TOKEN) {
                outputSignatures.push_back(PrivateKey(out.tokenKey).Sign(outHash));
            }
        }
    }

    while (true) {
        CMutableTransaction tx = this->tx;
        tx.nVersion |= CTransaction::BLSCT_MARKER;

        Scalar gammaAcc = outputGammas;
        std::map<TokenId, CAmount> mapChange;
        std::map<TokenId, CAmount> mapInputs;
        std::vector<Signature> txSigs = outputSignatures;

        if (type == STAKED_COMMITMENT_UNSTAKE || type == STAKED_COMMITMENT) {
            for (auto& in_ : vInputs) {
                for (auto& in : in_.second) {
                    if (!in.is_staked_commitment) continue;
                    if (!mapInputs[in_.first]) mapInputs[in_.first] = 0;
                    if (mapInputs[in_.first] > nAmounts[in_.first].nFromOutputs) break;

                    tx.vin.push_back(in.in);
                    gammaAcc = gammaAcc + in.gamma;
                    txSigs.push_back(in.sk.Sign(in.in.GetHash()));

                    mapInputs[in_.first] += in.value.GetUint64();
                }
            }
        }

        for (auto& in_ : vInputs) {
            for (auto& in : in_.second) {
                if (in.is_staked_commitment) continue;
                if (!mapInputs[in_.first]) mapInputs[in_.first] = 0;
                if (mapInputs[in_.first] > nAmounts[in_.first].nFromOutputs + nAmounts[in_.first].nFromFee) break;

                tx.vin.push_back(in.in);
                gammaAcc = gammaAcc + in.gamma;
                txSigs.push_back(in.sk.Sign(in.in.GetHash()));
                mapInputs[in_.first] += in.value.GetUint64();
            }
        }

        for (auto& amounts : nAmounts) {
            auto tokenFee = nAmounts[amounts.first].nFromFee;

            auto nFromInputs = mapInputs[amounts.first];

            if (nFromInputs < amounts.second.nFromOutputs + tokenFee) return std::nullopt;

            mapChange[amounts.first] = nFromInputs - amounts.second.nFromOutputs - tokenFee;
        }

        for (auto& change : mapChange) {
            if (change.second == 0) continue;

            auto changeOutput = CreateOutput(changeDestination, change.second, "Change", change.first, MclScalar::Rand(), NORMAL, minStake);

            gammaAcc = gammaAcc - changeOutput.gamma;

            tx.vout.push_back(changeOutput.out);
            txSigs.push_back(PrivateKey(changeOutput.blindingKey).Sign(changeOutput.out.GetHash()));
        }

        if (nAmounts[TokenId()].nFromFee == GetTransactionWeight(CTransaction(tx)) * BLSCT_DEFAULT_FEE) {
            CTxOut fee_out{nAmounts[TokenId()].nFromFee, CScript(OP_RETURN)};

            auto feeKey = blsct::PrivateKey(MclScalar::Rand());
            fee_out.predicate = blsct::PayFeePredicate(feeKey.GetPublicKey()).GetVch();

            tx.vout.push_back(fee_out);
            txSigs.push_back(PrivateKey(gammaAcc).SignBalance());
            txSigs.push_back(PrivateKey(feeKey).SignFee());

            tx.txSig = Signature::Aggregate(txSigs);

            return tx;
        }

        nAmounts[TokenId()].nFromFee = GetTransactionWeight(CTransaction(tx)) * BLSCT_DEFAULT_FEE;
    }

    return std::nullopt;
}

std::optional<CMutableTransaction> TxFactoryBase::CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const CreateTransactionData& transactionData)
{
    auto tx = blsct::TxFactoryBase();

    if (transactionData.type == STAKED_COMMITMENT) {
        CAmount inputFromStakedCommitments = 0;

        for (const auto& output : inputCandidates) {
            if (output.is_staked_commitment)
                inputFromStakedCommitments += output.amount;

            tx.AddInput(output.amount, output.gamma, output.spendingKey, output.token_id, COutPoint(output.outpoint.hash, output.outpoint.n), output.is_staked_commitment);
        }

        if (transactionData.nAmount + inputFromStakedCommitments < transactionData.minStake) {
            throw std::runtime_error(strprintf("A minimum of %s is required to stake", FormatMoney(transactionData.minStake)));
        }

        bool fSubtractFeeFromAmount = false; // nAmount == inAmount + inputFromStakedCommitments;

        tx.AddOutput(transactionData.destination, transactionData.nAmount + inputFromStakedCommitments, transactionData.sMemo, transactionData.token_id, transactionData.type, transactionData.minStake, fSubtractFeeFromAmount);
    } else {
        CAmount inputFromStakedCommitments = 0;

        for (const auto& output : inputCandidates) {
            if (output.is_staked_commitment) {
                if (!(transactionData.type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE || transactionData.type == CreateTransactionType::STAKED_COMMITMENT))
                    continue;
                inputFromStakedCommitments += output.amount;
            }

            tx.AddInput(output.amount, output.gamma, output.spendingKey, output.token_id, COutPoint(output.outpoint.hash, output.outpoint.n), output.is_staked_commitment);
        }

        if (transactionData.type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE) {
            if (inputFromStakedCommitments - transactionData.nAmount < 0) {
                throw std::runtime_error(strprintf("Not enough staked coins"));
            } else if (inputFromStakedCommitments - transactionData.nAmount < transactionData.minStake && inputFromStakedCommitments - transactionData.nAmount > 0) {
                throw std::runtime_error(strprintf("A minimum of %s is required to stake", FormatMoney(transactionData.minStake)));
            }

            if (inputFromStakedCommitments - transactionData.nAmount > 0) {
                // CHANGE
                tx.AddOutput(transactionData.destination, inputFromStakedCommitments - transactionData.nAmount, transactionData.sMemo, transactionData.token_id, CreateTransactionType::STAKED_COMMITMENT, transactionData.minStake, false);
            }
        }

        //bool fSubtractFeeFromAmount = false; // type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE;

        if (transactionData.type == TX_CREATE_TOKEN) {
            tx.AddOutput(transactionData.tokenKey, transactionData.tokenInfo);
        } else if (transactionData.type == TX_MINT_TOKEN) {
            if (!transactionData.token_id.IsNFT()) {
                tx.AddOutput(transactionData.tokenKey, transactionData.destination, transactionData.tokenInfo.publicKey, transactionData.nAmount);
            } else {
                tx.AddOutput(transactionData.tokenKey, transactionData.destination, transactionData.tokenInfo.publicKey, transactionData.token_id.subid, transactionData.nftMetadata);
            }
        } else if (transactionData.type == NORMAL) {
            tx.AddOutput(transactionData.destination, transactionData.nAmount, transactionData.sMemo, transactionData.token_id, transactionData.type);
        }
    }

    return tx.BuildTx(transactionData.changeDestination, transactionData.minStake, transactionData.type);
}

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

void TxFactoryBase::AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const wallet::CoinFilterParams& coins_params, std::vector<InputCandidates>& inputCandidates)
{
    AssertLockHeld(wallet->cs_wallet);
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

void TxFactoryBase::AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const TokenId& token_id, const CreateTransactionType& type, std::vector<InputCandidates>& inputCandidates)
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

std::optional<CMutableTransaction> TxFactory::CreateTransaction(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, CreateTransactionData transactionData)
{
    LOCK(wallet->cs_wallet);

    std::vector<InputCandidates> inputCandidates;

    TxFactoryBase::AddAvailableCoins(wallet, blsct_km, transactionData.token_id, transactionData.type, inputCandidates);

    auto changeType = transactionData.type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE ? STAKING_ACCOUNT : CHANGE_ACCOUNT;

    transactionData.changeDestination = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(changeType).value());

    if (transactionData.type == TX_CREATE_TOKEN || transactionData.type == TX_MINT_TOKEN) {
        transactionData.tokenKey = blsct_km->GetTokenKey((HashWriter{} << transactionData.tokenInfo.mapMetadata << transactionData.tokenInfo.nTotalSupply).GetHash()).GetScalar();
    }

    return TxFactoryBase::CreateTransaction(inputCandidates, transactionData);
}

} // namespace blsct
