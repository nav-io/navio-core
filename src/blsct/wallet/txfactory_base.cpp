// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory_base.h>
#include <util/rbf.h>

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
        nAmounts[token_id] = {0, 0};

    nAmounts[token_id].nFromOutputs += nAmount - nFee;

    if (vOutputs.count(token_id) == 0)
        vOutputs[token_id] = std::vector<UnsignedOutput>();

    vOutputs[token_id].push_back(out);
}

bool TxFactoryBase::AddInput(const CAmount& amount, const MclScalar& gamma, const PrivateKey& spendingKey, const TokenId& token_id, const COutPoint& outpoint, const bool& rbf)
{
    if (vInputs.count(token_id) == 0)
        vInputs[token_id] = std::vector<UnsignedInput>();

    vInputs[token_id].push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), amount, gamma, spendingKey});

    if (nAmounts.count(token_id) == 0)
        nAmounts[token_id] = {0, 0};

    nAmounts[token_id].nFromInputs += amount;

    return true;
}

std::optional<CMutableTransaction>
TxFactoryBase::BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake, const CreateTransactionType& type, const bool& fSubtractedFee)
{
    this->tx = CMutableTransaction();

    std::vector<Signature> outputSignatures;
    Scalar outputGammas;
    CAmount nFee = 0;

    for (auto& out_ : vOutputs) {
        for (auto& out : out_.second) {
            this->tx.vout.push_back(out.out);
            outputGammas = outputGammas - out.gamma;
            outputSignatures.push_back(PrivateKey(out.blindingKey).Sign(out.out.GetHash()));
        }
    }

    while (true) {
        CMutableTransaction tx = this->tx;
        tx.nVersion |= CTransaction::BLSCT_MARKER;

        Scalar gammaAcc = outputGammas;
        std::map<TokenId, CAmount> mapChange;
        std::map<TokenId, CAmount> mapInputs;
        std::vector<Signature> txSigs = outputSignatures;

        for (auto& in_ : vInputs) {
            auto tokenFee = (in_.first == TokenId() ? nFee : 0);

            for (auto& in : in_.second) {
                tx.vin.push_back(in.in);
                gammaAcc = gammaAcc + in.gamma;
                txSigs.push_back(in.sk.Sign(in.in.GetHash()));

                if (!mapInputs[in_.first]) mapInputs[in_.first] = 0;

                mapInputs[in_.first] += in.value.GetUint64();

                if (mapInputs[in_.first] > nAmounts[in_.first].nFromOutputs + nFee) break;
            }
        }

        for (auto& amounts : nAmounts) {
            auto tokenFee = (amounts.first == TokenId() ? nFee : 0);

            auto nFromInputs = mapInputs[amounts.first];

            if (nFromInputs < amounts.second.nFromOutputs + tokenFee) return std::nullopt;

            mapChange[amounts.first] = nFromInputs - amounts.second.nFromOutputs - tokenFee;
        }

        for (auto& change : mapChange) {
            if (change.second == 0) continue;

            auto changeOutput = CreateOutput(changeDestination, change.second, "Change", change.first, MclScalar::Rand(), type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE ? STAKED_COMMITMENT : NORMAL, minStake);

            gammaAcc = gammaAcc - changeOutput.gamma;

            tx.vout.push_back(changeOutput.out);
            txSigs.push_back(PrivateKey(changeOutput.blindingKey).Sign(changeOutput.out.GetHash()));
        }

        if (nFee == GetTransactionWeight(CTransaction(tx)) * BLSCT_DEFAULT_FEE) {
            CTxOut fee_out{nFee, CScript(OP_RETURN)};

            tx.vout.push_back(fee_out);
            txSigs.push_back(PrivateKey(gammaAcc).SignBalance());
            tx.txSig = Signature::Aggregate(txSigs);

            return tx;
        }

        nFee = GetTransactionWeight(CTransaction(tx)) * BLSCT_DEFAULT_FEE;
    }

    return std::nullopt;
}

std::optional<CMutableTransaction> TxFactoryBase::CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const blsct::DoublePublicKey& changeDestination, const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id, const CreateTransactionType& type, const CAmount& minStake)
{
    auto tx = blsct::TxFactoryBase();
    CAmount inAmount = 0;

    if (type == STAKED_COMMITMENT) {
        CAmount inputFromStakedCommitments = 0;

        for (const auto& output : inputCandidates) {
            if (output.is_staked_commitment)
                inputFromStakedCommitments += output.amount;
            if (!output.is_staked_commitment)
                inAmount += output.amount;

            tx.AddInput(output.amount, output.gamma, output.spendingKey, output.token_id, COutPoint(output.outpoint.hash, output.outpoint.n));
        }

        if (nAmount + inputFromStakedCommitments < minStake) {
            throw std::runtime_error(strprintf("A minimum of %s is required to stake", FormatMoney(minStake)));
        }

        bool fSubtractFeeFromAmount = false; // nAmount == inAmount + inputFromStakedCommitments;

        tx.AddOutput(destination, nAmount + inputFromStakedCommitments, sMemo, token_id, type, minStake, fSubtractFeeFromAmount);
    } else {
        for (const auto& output : inputCandidates) {
            tx.AddInput(output.amount, output.gamma, output.spendingKey, output.token_id, COutPoint(output.outpoint.hash, output.outpoint.n));
        }

        bool fSubtractFeeFromAmount = false; // type == CreateTransactionType::STAKED_COMMITMENT_UNSTAKE;

        tx.AddOutput(destination, nAmount, sMemo, token_id, type, minStake, fSubtractFeeFromAmount);
    }

    return tx.BuildTx(changeDestination, minStake, type);
}

} // namespace blsct
