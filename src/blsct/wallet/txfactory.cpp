// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/tokens/predicate_parser.h>
#include <blsct/wallet/txfactory.h>
#include <chainparams.h>
#include <limits>

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

    if (!vInputs.contains(coin.out.tokenId))
        vInputs[coin.out.tokenId] = std::vector<UnsignedInput>();

    try {
        blsct::PrivateKey spending_key;
        if (!km->GetSpendingKeyForOutputWithCache(coin.out, spending_key)) {
            return false;
        }
        vInputs[coin.out.tokenId].emplace_back(CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), recoveredInfo.amounts[0].amount, recoveredInfo.amounts[0].gamma, spending_key, stakedCommitment);
    } catch (const std::exception& e) {
        LogPrintf("Error adding input: %s\n", e.what());
        return false;
    }

    if (!nAmounts.contains(coin.out.tokenId))
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
        auto tx = wallet->GetWalletTxFromOutpoint(outpoint);

        if (tx == nullptr)
            return false;

        auto txout_iter = std::find_if(tx->tx->vout.begin(), tx->tx->vout.end(), [&](const CTxOut& out) { return out.GetHash() == outpoint.hash; });

        if (txout_iter == tx->tx->vout.end())
            return false;

        recoveredInfo = tx->GetBLSCTRecoveryData(outpoint);
    }

    if (!vInputs.contains(out.tokenId))
        vInputs[out.tokenId] = std::vector<UnsignedInput>();

    try {
        blsct::PrivateKey spending_key;
        if (!km->GetSpendingKeyForOutputWithCache(out, spending_key)) {
            return false;
        }
        vInputs[out.tokenId]
            .emplace_back(CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), recoveredInfo.amount, recoveredInfo.gamma, spending_key, stakedCommitment);
    } catch (const std::exception& e) {
        LogPrintf("Error adding input: %s\n", e.what());
        return false;
    }

    if (!nAmounts.contains(out.tokenId))
        nAmounts[out.tokenId] = {0, 0, 0};

    nAmounts[out.tokenId].nFromInputs += recoveredInfo.amount;

    return true;
}

std::optional<CMutableTransaction>
TxFactory::BuildTx()
{
    return TxFactoryBase::BuildTx(
        std::get<blsct::DoublePublicKey>(km->GetNewDestination(-1).value()),
        /*minStake=*/0,
        /*type=*/NORMAL,
        /*fSubtractedFee=*/false,
        Params().GetConsensus().nBLSCTDefaultFee);
}

std::optional<CMutableTransaction> TxFactory::CreateTransaction(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, CreateTransactionData transactionData)
{
    LOCK(wallet->cs_wallet);

    if (transactionData.nBLSCTDefaultFee == ::BLSCT_DEFAULT_FEE) {
        transactionData.nBLSCTDefaultFee = Params().GetConsensus().nBLSCTDefaultFee;
    }

    std::vector<InputCandidates> inputCandidates;

    TxFactory::AddAvailableCoins(wallet, blsct_km, transactionData.token_id, transactionData.type, inputCandidates, transactionData.nAmount, transactionData.fConsolidateStakedCommitments);

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

    bool is_blsct_storage = wallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE);
    auto availableCoins = is_blsct_storage ? AvailableBlsctCoins(*wallet, nullptr, coins_params) : AvailableCoins(*wallet, nullptr, std::nullopt, coins_params);

    // Recover every candidate first, then select largest-value-first below.
    // Selecting in wallet order would pile in many small outputs (e.g. the
    // numerous PoS staking rewards) to reach the target, producing oversized
    // BLSCT transactions -- range proofs are large -- that hit the standard
    // tx-size limit and, when chained, the mempool descendant-size limit.
    // Largest-first keeps the input count, and therefore the tx size, minimal.
    std::vector<InputCandidates> gathered;
    for (const wallet::COutput& output : availableCoins.All()) {
        CTxOut out;
        range_proof::RecoveredData<Mcl> recoveredInfo;

        bool isStakedCommitment = false;
        if (wallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE)) {
            auto wout = wallet->GetWalletOutput(output.outpoint);

            if (wout == nullptr)
                continue;

            out = *(wout->out);

            recoveredInfo = wout->blsctRecoveryData;
            isStakedCommitment = wout->fStakedCommitment;
        } else {
            auto tx = wallet->GetWalletTxFromOutpoint(output.outpoint);

            if (tx == nullptr) {
                continue;
            }

            auto txout_iter = std::find_if(tx->tx->vout.begin(), tx->tx->vout.end(), [&](const CTxOut& out) { return out.GetHash() == output.outpoint.hash; });

            if (txout_iter == tx->tx->vout.end()) {
                continue;
            }

            out = *txout_iter;

            recoveredInfo = tx->GetBLSCTRecoveryData(output.outpoint);
            isStakedCommitment = out.IsStakedCommitment();
        }
        auto value = (out.HasBLSCTRangeProof() || wallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE)) ? recoveredInfo.amount : out.nValue;

        try {
            blsct::PrivateKey spending_key;
            if (!blsct_km->GetSpendingKeyForOutputWithCache(out, spending_key)) {
                continue;
            }
            gathered.push_back({value, recoveredInfo.gamma, spending_key, out.tokenId, COutPoint(output.outpoint.hash), isStakedCommitment});
        } catch (const std::exception& e) {
            LogPrintf("Error adding input: %s\n", e.what());
            continue;
        }
    }

    // Staked commitments are kept ahead of ordinary coins so the staked-input
    // pass in BuildTx still sees them. Within each group the ordering differs:
    // ordinary coins are taken largest-first (so a wallet of many small outputs
    // does not pile thousands of tiny inputs into one tx), while staked
    // commitments are taken smallest-first so an unstake consumes the minimal
    // commitment(s) needed and leaves large stakes intact instead of splitting
    // a big commitment.
    std::sort(gathered.begin(), gathered.end(), [](const InputCandidates& a, const InputCandidates& b) {
        if (a.is_staked_commitment != b.is_staked_commitment) return a.is_staked_commitment;
        if (a.is_staked_commitment) return a.amount < b.amount;
        return a.amount > b.amount;
    });

    CAmount nTotalAdded = 0;
    for (auto& candidate : gathered) {
        inputCandidates.push_back(candidate);
        nTotalAdded += candidate.amount;

        if (nTotalAdded > nAmountLimit)
            break;
    }
}

void TxFactory::AddAvailableCoins(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const TokenId& token_id, const CreateTransactionType& type, std::vector<InputCandidates>& inputCandidates, const CAmount& nAmountLimit, const bool& consolidateStakedCommitments)
{
    AssertLockHeld(wallet->cs_wallet);

    wallet::CoinFilterParams coins_params;
    coins_params.min_amount = 0;
    coins_params.only_blsct = true;
    coins_params.token_id = token_id;
    // Gather all spendable coins (not just enough to reach the target in wallet
    // order). AddAvailableCoins selects largest-value-first, so we must let it
    // see the large outputs; otherwise AvailableCoins stops early at min_sum and
    // only the small staking outputs are considered, producing oversized txs.
    coins_params.min_sum_amount = MAX_MONEY;

    AddAvailableCoins(wallet, blsct_km, coins_params, inputCandidates, nAmountLimit + COIN);

    // Whether this transaction must pull in the wallet's existing staked
    // commitments. Unstaking always must (the commitments are the funds being
    // spent). Staking only does so when consolidating — with consolidation
    // disabled, `stakelock` funds a fresh, separate commitment from spendable
    // coins instead of folding the prior commitments in.
    const bool gather_staked = (type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE) ||
                               (type == CreateTransactionType::STAKED_COMMITMENT && consolidateStakedCommitments);

    if (gather_staked) {
        coins_params.include_staked_commitment = true;

        // When consolidating we merge the whole stake into one output; without
        // consolidation we only need enough commitments to cover the requested
        // amount, leaving the rest intact as separate stakes.
        CAmount stakeCoinLimit = consolidateStakedCommitments
                                     ? CAmount(999000000) * COIN // effectively all
                                     : nAmountLimit;

        // Always let AvailableCoins surface EVERY staked commitment (not just
        // enough to reach the target in wallet-iteration order). The selection
        // in the inner AddAvailableCoins then sorts them smallest-first and
        // takes the minimal set covering stakeCoinLimit. Stopping the gather
        // early (min_sum_amount = stakeCoinLimit) left the choice of which
        // commitment is seen first up to wallet order, which is platform
        // dependent -- an unstake could split a large commitment instead of
        // consuming a smaller exact one, producing a different (wrong) result.
        coins_params.min_sum_amount = MAX_MONEY;
        coins_params.skip_locked = false;

        AddAvailableCoins(wallet, blsct_km, coins_params, inputCandidates, stakeCoinLimit);
    }

    if ((type == CreateTransactionType::NORMAL && !token_id.IsNull()) || type == CreateTransactionType::TX_MINT_TOKEN) {
        coins_params.token_id.SetNull();
        coins_params.min_sum_amount = COIN;
        AddAvailableCoins(wallet, blsct_km, coins_params, inputCandidates, COIN);
    }
}

std::optional<CMutableTransaction> TxFactory::CreateConsolidationTransaction(wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const blsct::DoublePublicKey& destination, const size_t& maxInputs, const CAmount& nBLSCTDefaultFee)
{
    AssertLockHeld(wallet->cs_wallet);

    // Gather every spendable native-token (non-staked) coin, then merge the
    // SMALLEST ones first -- that is what reduces the output count fastest.
    std::vector<InputCandidates> candidates;
    AddAvailableCoins(wallet, blsct_km, TokenId(), CreateTransactionType::NORMAL, candidates, MAX_MONEY);

    std::erase_if(candidates, [](const InputCandidates& c) {
        return c.is_staked_commitment || !c.token_id.IsNull();
    });
    std::sort(candidates.begin(), candidates.end(), [](const InputCandidates& a, const InputCandidates& b) {
        return a.amount < b.amount;
    });

    const size_t n = std::min({maxInputs, candidates.size(), MAX_TX_INPUT_COUNT});
    // Nothing to do unless at least two outputs can be merged into one.
    if (n < 2) return std::nullopt;

    TxFactoryBase factory;
    CAmount nSum = 0;
    for (size_t i = 0; i < n; ++i) {
        factory.AddInput(candidates[i].amount, candidates[i].gamma, candidates[i].spendingKey, TokenId(), candidates[i].outpoint);
        nSum += candidates[i].amount;
    }

    // One output back to `destination`; the fee is taken from the merged amount.
    factory.AddOutput(SubAddress(destination), nSum, "Consolidate", TokenId(), NORMAL, 0, /*fSubtractFeeFromAmount=*/true, MclScalar::Rand(), nBLSCTDefaultFee);

    return factory.BuildTx(destination, /*minStake=*/0, NORMAL, /*fSubtractedFee=*/true, nBLSCTDefaultFee);
}

} // namespace blsct
