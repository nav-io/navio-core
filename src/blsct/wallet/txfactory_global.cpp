// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/tokens/predicate_parser.h>
#include <blsct/wallet/txfactory_global.h>

using T = Mcl;
using Point = T::Point;
using Points = Elements<Point>;
using Scalar = T::Scalar;
using Scalars = Elements<Scalar>;

namespace blsct {
void UnsignedOutput::GenerateKeys(Scalar blindingKey, DoublePublicKey destKeys)
{
    out.blsctData.ephemeralKey = PrivateKey(blindingKey).GetPoint();

    Point vk, sk;

    if (!destKeys.GetViewKey(vk)) {
        throw std::runtime_error(strprintf("%s: could not get view key from destination address\n", __func__));
    }

    if (!destKeys.GetSpendKey(sk)) {
        throw std::runtime_error(strprintf("%s: could not get spend key from destination address\n", __func__));
    }

    out.blsctData.blindingKey = sk * blindingKey;

    auto rV = vk * blindingKey;

    out.blsctData.spendingKey = sk + (PrivateKey(Scalar(rV.GetHashWithSalt(0))).GetPoint());
}

Signature UnsignedOutput::GetSignature() const
{
    std::vector<Signature> txSigs;

    txSigs.push_back(blsct::PrivateKey(blindingKey).Sign(out.GetHash()));
    txSigs.push_back(blsct::PrivateKey(gamma.Negate()).SignBalance());

    return Signature::Aggregate(txSigs);
}

UnsignedOutput CreateOutput(const Scalar& tokenKey, const blsct::TokenInfo& tokenInfo)
{
    auto ret = CreateOutput(blsct::DoublePublicKey(), 0, "", TokenId(), Scalar::Rand(), TX_CREATE_TOKEN);

    ret.out.predicate = CreateTokenPredicate(tokenInfo).GetVch();
    ret.tokenKey = tokenKey;

    return ret;
}

UnsignedOutput CreateOutput(const blsct::DoublePublicKey& destKeys, const CAmount& nAmount, const Scalar& blindingKey, const Scalar& tokenKey, const blsct::PublicKey& tokenPublicKey)
{
    TokenId tokenId{tokenPublicKey.GetHash()};

    auto ret = CreateOutput(destKeys, nAmount, "", tokenId, blindingKey, TX_MINT_TOKEN);

    if (!tokenId.IsNFT()) {
        ret.out.predicate = MintTokenPredicate(tokenPublicKey, nAmount).GetVch();
    }
    ret.tokenKey = tokenKey;

    return ret;
}

UnsignedOutput CreateOutput(const blsct::DoublePublicKey& destKeys, const Scalar& blindingKey, const Scalar& tokenKey, const blsct::PublicKey& tokenPublicKey, const CAmount& nftId, const std::map<std::string, std::string>& nftMetadata)
{
    TokenId tokenId{tokenPublicKey.GetHash(), nftId};

    auto ret = CreateOutput(destKeys, 1, "", tokenId, blindingKey, TX_MINT_TOKEN);

    if (tokenId.IsNFT()) {
        ret.out.predicate = MintNftPredicate(tokenPublicKey, nftId, nftMetadata).GetVch();
    }
    ret.tokenKey = tokenKey;

    return ret;
}

UnsignedOutput CreateOutput(const blsct::DoublePublicKey& destKeys, const CAmount& nAmount, std::string sMemo, const TokenId& tokenId, const Scalar& blindingKey, const CreateTransactionType& type, const CAmount& minStake)
{
    bulletproofs_plus::RangeProofLogic<T> rp;
    auto ret = UnsignedOutput();

    ret.type = type;

    ret.out.nValue = 0;
    ret.out.tokenId = tokenId;

    Scalars vs;
    vs.Add(nAmount);

    ret.blindingKey = blindingKey.IsZero() ? MclScalar::Rand() : blindingKey;

    Points nonces;
    Point vk;

    if (!destKeys.GetViewKey(vk)) {
        throw std::runtime_error(strprintf("%s: could not get view key from destination address\n", __func__));
    }

    auto nonce = vk * ret.blindingKey;
    nonces.Add(nonce);

    ret.value = nAmount;
    ret.gamma = nonce.GetHashWithSalt(100);

    std::vector<unsigned char> memo{sMemo.begin(), sMemo.end()};

    if (nAmount > 0) {
        ret.out.scriptPubKey = CScript(OP_TRUE);

        if (type == STAKED_COMMITMENT && tokenId.IsNull()) {
            auto stakeRp = rp.Prove(vs, nonce, {}, tokenId, minStake);

            stakeRp.Vs.Clear();

            DataStream ss{};
            ss << stakeRp;

            ret.out.scriptPubKey = CScript() << OP_STAKED_COMMITMENT << blsct::Common::DataStreamToVector(ss) << OP_DROP << OP_TRUE;
        }
        if (tokenId.IsNFT()) {
            ret.out.nValue = nAmount;
        } else {
            auto p = rp.Prove(vs, nonce, memo, tokenId);
            ret.out.blsctData.rangeProof = p;
        }
        ret.GenerateKeys(ret.blindingKey, destKeys);
        HashWriter hash{};
        hash << nonce;
        ret.out.blsctData.viewTag = (hash.GetHash().GetUint64(0) & 0xFFFF);
    } else {
        ret.out.scriptPubKey = CScript(OP_RETURN);
    }

    return ret;
}

CTransactionRef AggregateTransactions(const std::vector<CTransactionRef>& txs)
{
    auto ret = CMutableTransaction();
    std::vector<Signature> vSigs;
    CAmount nFee = 0;
    std::vector<blsct::PublicKey> feePublicKeys;

    for (auto& tx : txs) {
        vSigs.push_back(tx->txSig);
        for (auto& in : tx->vin) {
            ret.vin.push_back(in);
        }
        for (auto& out : tx->vout) {
            if (out.IsFee()) {
                if (out.predicate.size() > 0) {
                    auto parsedPredicate = blsct::ParsePredicate(out.predicate);
                    if (parsedPredicate.IsPayFeePredicate()) {
                        feePublicKeys.push_back(parsedPredicate.GetPublicKey());
                        nFee += out.nValue;
                        continue;
                    }
                }
            }
            ret.vout.push_back(out);
        }
    }

    CTxOut feeOut(nFee, CScript{OP_RETURN});
    feeOut.predicate = blsct::PayFeePredicate(blsct::PublicKeys(feePublicKeys).Aggregate()).GetVch();

    ret.vout.emplace_back(feeOut);

    ret.txSig = blsct::Signature::Aggregate(vSigs);
    ret.nVersion = CTransaction::BLSCT_MARKER;

    return MakeTransactionRef(ret);
}

int32_t GetTransactionWeight(const CTransaction& tx)
{
    return ::GetSerializeSize(TX_WITH_WITNESS(tx));
}

int32_t GetTransactioOutputWeight(const CTxOut& out)
{
    return ::GetSerializeSize(out);
}
} // namespace blsct
