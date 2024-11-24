// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TXFACTORY_GLOBAL_H
#define TXFACTORY_GLOBAL_H

#include <blsct/double_public_key.h>
#include <blsct/public_keys.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/tokens/info.h>
#include <primitives/transaction.h>

using T = Mcl;
using Point = T::Point;
using Points = Elements<Point>;
using Scalar = T::Scalar;
using Scalars = Elements<Scalar>;

#define BLSCT_DEFAULT_FEE 125

namespace blsct {
enum CreateTransactionType {
    NORMAL,
    STAKED_COMMITMENT,
    STAKED_COMMITMENT_UNSTAKE,
    TX_CREATE_TOKEN,
    TX_MINT_TOKEN
};

struct UnsignedOutput {
    CTxOut out;
    Scalar blindingKey;
    Scalar value;
    Scalar gamma;
    Scalar tokenKey;
    CreateTransactionType type;

    void
    GenerateKeys(Scalar blindingKey, DoublePublicKey destKeys);

    Signature GetSignature() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, out);
        ::Serialize(s, blindingKey);
        ::Serialize(s, value);
        ::Serialize(s, gamma);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, out);
        ::Unserialize(s, blindingKey);
        ::Unserialize(s, value);
        ::Unserialize(s, gamma);
    }
};

struct UnsignedInput {
    CTxIn in;
    Scalar value;
    Scalar gamma;
    PrivateKey sk;
    bool is_staked_commitment;
};

struct Amounts {
    CAmount nFromInputs;
    CAmount nFromOutputs;
    CAmount nFromFee;
};

CTransactionRef
AggregateTransactions(const std::vector<CTransactionRef>& txs);
UnsignedOutput CreateOutput(const Scalar& tokenKey, const blsct::TokenInfo& tokenInfo);
UnsignedOutput CreateOutput(const Scalar& tokenKey, const blsct::TokenInfo& tokenInfo);
UnsignedOutput CreateOutput(const blsct::DoublePublicKey& destKeys, const CAmount& nAmount, const Scalar& blindingKey, const Scalar& tokenKey, const blsct::PublicKey& tokenPublicKey);
UnsignedOutput CreateOutput(const blsct::DoublePublicKey& destKeys, const Scalar& blindingKey, const Scalar& tokenKey, const blsct::PublicKey& tokenPublicKey, const uint64_t& nftId, const std::map<std::string, std::string>& nftMetadata);
UnsignedOutput CreateOutput(const blsct::DoublePublicKey& destination, const CAmount& nAmount, std::string sMemo, const TokenId& tokenId = TokenId(), const Scalar& blindingKey = Scalar::Rand(), const CreateTransactionType& type = NORMAL, const CAmount& minStake = 0);
int32_t GetTransactionWeight(const CTransaction& tx);
int32_t GetTransactioOutputWeight(const CTxOut& out);
} // namespace blsct

#endif // TXFACTORY_GLOBAL_H
