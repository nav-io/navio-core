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

void TxFactoryBase::AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& tokenId, const CreateOutputType& type, const CAmount& minStake)
{
    UnsignedOutput out;
    out = CreateOutput(destination.GetKeys(), nAmount, sMemo, tokenId, Scalar::Rand(), type, minStake);

    if (nAmounts.count(tokenId) == 0)
        nAmounts[tokenId] = {0, 0};

    nAmounts[tokenId].nFromOutputs += nAmount;

    if (vOutputs.count(tokenId) == 0)
        vOutputs[tokenId] = std::vector<UnsignedOutput>();

    vOutputs[tokenId].push_back(out);
}


bool TxFactoryBase::AddInput(const CAmount& amount, const MclScalar& gamma, const PrivateKey& spendingKey, const TokenId& tokenId, const COutPoint& outpoint, const bool& rbf)
{
    if (vInputs.count(tokenId) == 0)
        vInputs[tokenId] = std::vector<UnsignedInput>();

    vInputs[tokenId].push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), amount, gamma, spendingKey});

    if (nAmounts.count(tokenId) == 0)
        nAmounts[tokenId] = {0, 0};

    nAmounts[tokenId].nFromInputs += amount;

    return true;
}

std::optional<CMutableTransaction>
TxFactoryBase::BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake, const bool& fUnstake, const bool& fSubtractedFee)
{
    CAmount nFee = BLSCT_DEFAULT_FEE * (vInputs.size() + vOutputs.size());

    while (true) {
        CMutableTransaction tx;
        tx.nVersion |= CTransaction::BLSCT_MARKER;

        Scalar gammaAcc;
        std::map<TokenId, CAmount> mapChange;
        std::vector<Signature> txSigs;

        for (auto& amounts : nAmounts) {
            if (amounts.second.nFromInputs < amounts.second.nFromOutputs + nFee)
                return std::nullopt;
            mapChange[amounts.first] = amounts.second.nFromInputs - amounts.second.nFromOutputs - nFee;
        }

        for (auto& in_ : vInputs) {
            for (auto& in : in_.second) {
                tx.vin.push_back(in.in);
                gammaAcc = gammaAcc + in.gamma;
                txSigs.push_back(in.sk.Sign(in.in.GetHash()));
            }
        }

        for (auto& out_ : vOutputs) {
            for (auto& out : out_.second) {
                tx.vout.push_back(out.out);
                gammaAcc = gammaAcc - out.gamma;
                txSigs.push_back(PrivateKey(out.blindingKey).Sign(out.out.GetHash()));
            }
        }

        for (auto& change : mapChange) {
            if (change.second == 0) continue;
            auto changeOutput = CreateOutput(changeDestination, change.second, "Change", change.first, MclScalar::Rand(), fUnstake ? STAKED_COMMITMENT : NORMAL, minStake);
            tx.vout.push_back(changeOutput.out);
            gammaAcc = gammaAcc - changeOutput.gamma;
            txSigs.push_back(PrivateKey(changeOutput.blindingKey).Sign(changeOutput.out.GetHash()));
        }

        if (nFee == (long long)(BLSCT_DEFAULT_FEE * (tx.vin.size() + tx.vout.size()))) {
            CTxOut fee_out{nFee, CScript(OP_RETURN)};
            tx.vout.push_back(fee_out);
            txSigs.push_back(PrivateKey(gammaAcc).SignBalance());
            tx.txSig = Signature::Aggregate(txSigs);
            return tx;
        }

        nFee = BLSCT_DEFAULT_FEE * (tx.vin.size() + tx.vout.size());
    }

    return std::nullopt;
}

std::optional<CMutableTransaction> TxFactoryBase::CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const blsct::DoublePublicKey& changeDestination, const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& tokenId, const CreateOutputType& type, const CAmount& minStake, const bool& fUnstake)
{
    auto tx = blsct::TxFactoryBase();
    CAmount inAmount = 0;

    for (const auto& output : inputCandidates) {
        tx.AddInput(output.amount, output.gamma, output.spendingKey, output.tokenId, COutPoint(output.outpoint.hash, output.outpoint.n));
        inAmount += output.amount;
        if (tx.nAmounts[tokenId].nFromInputs > nAmount + (long long)(BLSCT_DEFAULT_FEE * (tx.vInputs.size() + 2))) break;
    }

    CAmount subtract = 0;
    bool fChangeNeeded = inAmount > nAmount;

    if (fUnstake)
        subtract = (BLSCT_DEFAULT_FEE * (tx.vInputs.size() + 1 + fChangeNeeded));

    tx.AddOutput(destination, nAmount - subtract, sMemo, tokenId, type, minStake);

    return tx.BuildTx(changeDestination, minStake, fUnstake);
}

} // namespace blsct
