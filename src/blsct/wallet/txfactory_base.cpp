// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory_base.h>
#include <util/rbf.h>

#include <random>

using T = Mcl;
using Point = T::Point;
using Points = Elements<Point>;
using Scalar = T::Scalar;
using Scalars = Elements<Scalar>;

namespace blsct {

void TxFactoryBase::AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id, const CreateTransactionType& type, const CAmount& minStake, const bool& fSubtractFeeFromAmount, const Scalar& blindingKey, const CAmount& nBLSCTDefaultFee, const std::optional<delegation::DelegationRequest>& stakeDelegation)
{
    if (!nAmounts.contains(token_id))
        nAmounts[token_id] = {0, 0, 0};

    if (fSubtractFeeFromAmount) {
        // The final value is (nAmount - total transaction fee), and the total
        // fee is only known once BuildTx's fee fixpoint converges. Defer the
        // output; BuildTx materializes it at the reduced value. Reuse the
        // supplied blindingKey across rebuilds so the deferral is deterministic.
        // Stake operations never subtract the fee, so a stake delegation
        // request cannot reach this path.
        subtractFeeOutput = SubtractFeeOutput{destination, nAmount, sMemo, token_id, type, minStake, blindingKey};
        return;
    }

    UnsignedOutput out = CreateOutput(destination.GetKeys(), nAmount, sMemo, token_id, blindingKey, type, minStake);

    if (stakeDelegation.has_value() && type == STAKED_COMMITMENT && token_id.IsNull()) {
        // Attach the encrypted opening of the just-built commitment so the
        // delegate can stake it. DATA predicates are consensus no-ops, and
        // the predicate is set before BuildTx() computes the output
        // signatures, so the payload is covered by the ownership signature.
        delegation::DelegationInfo info;
        info.value = nAmount;
        info.gamma = out.gamma;
        info.rewardAddress = stakeDelegation->rewardAddress;
        out.out.predicate = DataPredicate(delegation::Encrypt(info, stakeDelegation->delegateKey)).GetVch();
    }

    nAmounts[token_id].nFromOutputs += nAmount;

    if (!vOutputs.contains(token_id))
        vOutputs[token_id] = std::vector<UnsignedOutput>();

    vOutputs[token_id].push_back(out);
}

// Create token
void TxFactoryBase::AddOutput(const Scalar& tokenKey, const blsct::TokenInfo& tokenInfo)
{
    UnsignedOutput out;

    out = CreateOutput(tokenKey, tokenInfo);

    TokenId token_id{tokenInfo.publicKey.GetHash()};

    if (!vOutputs.contains(token_id))
        vOutputs[token_id] = std::vector<UnsignedOutput>();

    vOutputs[token_id].push_back(out);
}

// Mint Token

void TxFactoryBase::AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const CAmount& mintAmount)
{
    UnsignedOutput out;

    out = CreateOutput(destination.GetKeys(), mintAmount, Scalar::Rand(), tokenKey, tokenPublicKey);

    TokenId token_id{tokenPublicKey.GetHash()};

    if (!vOutputs.contains(token_id))
        vOutputs[token_id] = std::vector<UnsignedOutput>();

    vOutputs[token_id].push_back(out);
}

// Mint NFT

void TxFactoryBase::AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const uint64_t& nftId, const std::map<std::string, std::string>& nftMetadata)
{
    UnsignedOutput out;

    out = CreateOutput(destination.GetKeys(), Scalar::Rand(), tokenKey, tokenPublicKey, nftId, nftMetadata);

    TokenId token_id{tokenPublicKey.GetHash(), nftId};

    if (!vOutputs.contains(token_id))
        vOutputs[token_id] = std::vector<UnsignedOutput>();

    vOutputs[token_id].push_back(out);
}

std::optional<CMutableTransaction>
TxFactoryBase::BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake, const CreateTransactionType& type, const bool& fSubtractedFee, const CAmount& nBLSCTDefaultFee)
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

    // Select largest-value inputs first. The loops below add inputs in order
    // until the target is covered, so without this a wallet full of small
    // outputs (e.g. PoS staking rewards) would pile in many tiny inputs and
    // produce an oversized BLSCT transaction. Sorting descending keeps the
    // input count -- and therefore the tx size -- minimal.
    for (auto& in_ : vInputs) {
        std::sort(in_.second.begin(), in_.second.end(), [](const UnsignedInput& a, const UnsignedInput& b) {
            return a.value.GetUint64() > b.value.GetUint64();
        });
    }

    while (true) {
        CMutableTransaction tx = this->tx;
        tx.nVersion |= CTransaction::BLSCT_MARKER;

        Scalar gammaAcc = outputGammas;
        std::map<TokenId, CAmount> mapChange;
        std::map<TokenId, CAmount> mapInputs;
        std::vector<Signature> txSigs = outputSignatures;
        // Set if selection stops because the per-tx input cap is reached while
        // funds remain unselected -- i.e. the amount needs more inputs than fit
        // in one transaction. Distinguishes "consolidate first" from genuine
        // insufficient funds below.
        bool hitInputCap = false;

        // Materialize the deferred subtract-fee-from-amount recipient at
        // (amount - current fee estimate). BLSCT output size is
        // value-independent, so lowering the value does not change the fee and
        // the fixpoint still converges (typically in two passes). Setting
        // nFromOutputs to the reduced value makes input selection target the
        // original amount (reduced + fee), so the fee is routed out of the
        // recipient output rather than out of change.
        std::optional<UnsignedOutput> sffaOut;
        if (subtractFeeOutput) {
            const CAmount fee = nAmounts[TokenId()].nFromFee;
            const CAmount reduced = subtractFeeOutput->amount - fee;
            if (reduced < 0) return std::nullopt; // fee exceeds the amount sent
            nAmounts[subtractFeeOutput->token_id].nFromOutputs = reduced;
            sffaOut = CreateOutput(subtractFeeOutput->destination.GetKeys(), reduced,
                                   subtractFeeOutput->memo, subtractFeeOutput->token_id,
                                   subtractFeeOutput->blindingKey, subtractFeeOutput->type,
                                   subtractFeeOutput->minStake);
            gammaAcc = gammaAcc - sffaOut->gamma;
        }

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
                if (tx.vin.size() >= MAX_TX_INPUT_COUNT) {
                    hitInputCap = true;
                    break;
                }

                tx.vin.push_back(in.in);
                gammaAcc = gammaAcc + in.gamma;
                txSigs.push_back(in.sk.Sign(in.in.GetHash()));
                mapInputs[in_.first] += in.value.GetUint64();
            }
            if (hitInputCap) break;
        }
        for (auto& amounts : nAmounts) {
            auto tokenFee = nAmounts[amounts.first].nFromFee;

            auto nFromInputs = mapInputs[amounts.first];

            if (nFromInputs < amounts.second.nFromOutputs + tokenFee) {
                if (hitInputCap) {
                    throw std::runtime_error(strprintf(
                        "This transaction would need more than %u inputs (too many small outputs to spend at once). "
                        "Consolidate small outputs first with the 'consolidate' RPC, then retry.",
                        MAX_TX_INPUT_COUNT));
                }
                return std::nullopt;
            }

            mapChange[amounts.first] = nFromInputs - amounts.second.nFromOutputs - tokenFee;
        }
        for (auto& change : mapChange) {
            if (change.second == 0) continue;

            // For unstake txs the "change" output IS the unlocked portion
            // returning to the user — label it accordingly so clients (and
            // listtransactions memo field) can distinguish it from ordinary
            // change.
            const std::string change_memo = (type == STAKED_COMMITMENT_UNSTAKE)
                ? std::string{"Stake Unlock"}
                : std::string{"Change"};
            auto changeOutput = CreateOutput(changeDestination, change.second, change_memo, change.first, MclScalar::Rand(), NORMAL, minStake);

            gammaAcc = gammaAcc - changeOutput.gamma;

            tx.vout.push_back(changeOutput.out);
            txSigs.push_back(PrivateKey(changeOutput.blindingKey).Sign(changeOutput.out.GetHash()));
        }
        if (sffaOut) {
            tx.vout.push_back(sffaOut->out);
            txSigs.push_back(PrivateKey(sffaOut->blindingKey).Sign(sffaOut->out.GetHash()));
        }
        CTxOut fee_out{nAmounts[TokenId()].nFromFee, CScript(OP_RETURN)};

        auto feeKey = blsct::PrivateKey(MclScalar::Rand());
        fee_out.predicate = blsct::PayFeePredicate(feeKey.GetPublicKey()).GetVch();

        tx.vout.push_back(fee_out);
        txSigs.push_back(PrivateKey(gammaAcc).SignBalance());
        txSigs.push_back(PrivateKey(feeKey).SignFee());

        tx.txSig = Signature::Aggregate(txSigs);

        const CAmount required_fee = GetTransactionWeight(CTransaction(tx)) * nBLSCTDefaultFee;
        if (nAmounts[TokenId()].nFromFee == required_fee) {
            // Randomise input and output ordering so the on-chain transaction
            // does not leak the wallet's coin-selection order (e.g. that earlier
            // inputs correspond to larger outputs, or the change position). The
            // BLSCT aggregate signature and balance proof are order-independent,
            // so reordering does not affect validity. Seed a PRNG from BLSCT's
            // secure randomness (MclScalar::Rand) rather than FastRandomContext,
            // which lives outside the libblsct library this file is built into.
            std::seed_seq seed{MclScalar::Rand().GetUint64(), MclScalar::Rand().GetUint64(),
                               MclScalar::Rand().GetUint64(), MclScalar::Rand().GetUint64()};
            std::mt19937_64 rng(seed);
            std::shuffle(tx.vin.begin(), tx.vin.end(), rng);
            std::shuffle(tx.vout.begin(), tx.vout.end(), rng);
            return tx;
        }
        nAmounts[TokenId()].nFromFee = required_fee;
    }

    return std::nullopt;
}

bool TxFactoryBase::AddInput(const CAmount& amount, const MclScalar& gamma, const PrivateKey& spendingKey, const TokenId& token_id, const COutPoint& outpoint, const bool& stakedCommitment, const bool& rbf)
{
    if (!vInputs.contains(token_id))
        vInputs[token_id] = std::vector<UnsignedInput>();

    vInputs[token_id].emplace_back(CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), amount, gamma, spendingKey, stakedCommitment);

    if (!nAmounts.contains(token_id))
        nAmounts[token_id] = {0, 0, 0};

    nAmounts[token_id].nFromInputs += amount;

    return true;
}

std::optional<CMutableTransaction> TxFactoryBase::CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const CreateTransactionData& transactionData)
{
    auto tx = blsct::TxFactoryBase();

    if (transactionData.type == STAKED_COMMITMENT) {
        CAmount inputFromStakedCommitments = 0;

        for (const auto& output : inputCandidates) {
            if (output.is_staked_commitment) {
                // With consolidation disabled, leave existing commitments
                // untouched so this stakelock yields a separate commitment.
                if (!transactionData.fConsolidateStakedCommitments)
                    continue;
                inputFromStakedCommitments += output.amount;
            }

            tx.AddInput(output.amount, output.gamma, output.spendingKey, output.token_id, COutPoint(output.outpoint.hash), output.is_staked_commitment);
        }

        if (transactionData.nAmount + inputFromStakedCommitments < transactionData.minStake) {
            throw std::runtime_error(strprintf("A minimum of %s is required to stake", FormatMoney(transactionData.minStake)));
        }

        bool fSubtractFeeFromAmount = false; // nAmount == inAmount + inputFromStakedCommitments;

        tx.AddOutput(transactionData.destination, transactionData.nAmount + inputFromStakedCommitments, transactionData.sMemo, transactionData.token_id, transactionData.type, transactionData.minStake, fSubtractFeeFromAmount, Scalar::Rand(), transactionData.nBLSCTDefaultFee, transactionData.stakeDelegation);
    } else {
        CAmount inputFromStakedCommitments = 0;

        for (const auto& output : inputCandidates) {
            if (output.is_staked_commitment) {
                if (!(transactionData.type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE || transactionData.type == CreateTransactionType::STAKED_COMMITMENT))
                    continue;
                inputFromStakedCommitments += output.amount;
            }

            tx.AddInput(output.amount, output.gamma, output.spendingKey, output.token_id, COutPoint(output.outpoint.hash), output.is_staked_commitment);
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

        // bool fSubtractFeeFromAmount = false; // type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE;

        if (transactionData.type == TX_CREATE_TOKEN) {
            tx.AddOutput(transactionData.tokenKey, transactionData.tokenInfo);
        } else if (transactionData.type == TX_MINT_TOKEN) {
            if (!transactionData.token_id.IsNFT()) {
                tx.AddOutput(transactionData.tokenKey, transactionData.destination, transactionData.tokenInfo.publicKey, transactionData.nAmount);
            } else {
                tx.AddOutput(transactionData.tokenKey, transactionData.destination, transactionData.tokenInfo.publicKey, transactionData.token_id.subid, transactionData.nftMetadata);
            }
        } else if (transactionData.type == NORMAL) {
            // subtract-fee-from-amount is only meaningful for native-token
            // sends: the fee is always denominated in the native token.
            const bool subtract_fee = transactionData.fSubtractFeeFromAmount && transactionData.token_id.IsNull();
            tx.AddOutput(transactionData.destination, transactionData.nAmount, transactionData.sMemo, transactionData.token_id, transactionData.type, transactionData.minStake, subtract_fee, Scalar::Rand(), transactionData.nBLSCTDefaultFee);
        }
    }
    return tx.BuildTx(transactionData.changeDestination, transactionData.minStake, transactionData.type, /*fSubtractedFee=*/false, transactionData.nBLSCTDefaultFee);
}

} // namespace blsct
