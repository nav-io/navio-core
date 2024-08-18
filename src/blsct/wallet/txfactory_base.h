// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/txfactory_global.h>
#include <primitives/transaction.h>

namespace blsct {

struct InputCandidates {
    CAmount amount;
    MclScalar gamma;
    blsct::PrivateKey spendingKey;
    TokenId tokenId;
    COutPoint outpoint;
};

class TxFactoryBase
{
protected:
    CMutableTransaction tx;
    std::map<TokenId, std::vector<UnsignedOutput>> vOutputs;
    std::map<TokenId, std::vector<UnsignedInput>> vInputs;
    std::map<TokenId, Amounts> nAmounts;

public:
    TxFactoryBase(){};

    void AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& tokenId = TokenId(), const CreateOutputType& type = NORMAL, const CAmount& minStake = 0);

    bool AddInput(const CAmount& amount, const MclScalar& gamma, const blsct::PrivateKey& spendingKey, const TokenId& tokenId, const COutPoint& outpoint, const bool& rbf = false);

    std::optional<CMutableTransaction> BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake = 0, const bool& fUnstake = false, const bool& fSubtractedFee = false);

    static std::optional<CMutableTransaction> CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const blsct::DoublePublicKey& changeDestination, const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& tokenId = TokenId(), const CreateOutputType& type = NORMAL, const CAmount& minStake = 0, const bool& fUnstake = false);
};

} // namespace blsct
