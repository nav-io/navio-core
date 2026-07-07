// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/bridge_txfactory.h>

#include <blsct/tokens/predicate_parser.h>
#include <blsct/bridge/messages.h>
#include <chainparams.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <util/rbf.h>

#include <algorithm>
#include <random>
#include <set>

namespace blsct {
namespace bridge {

using MclT = Mcl;

// --- key derivation ----------------------------------------------------------

blsct::PrivateKey GetGuardianKey(blsct::KeyMan* blsct_km)
{
    static const std::string tag{"nbp/guardian/v1"};
    uint256 hash;
    CSHA256().Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size()).Finalize(hash.begin());
    return blsct_km->GetTokenKey(hash);
}

blsct::DoublePublicKey GetClaimDestination(blsct::KeyMan* blsct_km)
{
    return blsct_km->GetSubAddress(SubAddressIdentifier{0, 0}).GetKeys();
}

// --- signed messages (must match blsct/bridge/logic.cpp byte for byte) -------

std::vector<unsigned char> DstMessage(const std::string& dst, const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> msg;
    msg.reserve(dst.size() + payload.size());
    msg.insert(msg.end(), dst.begin(), dst.end());
    msg.insert(msg.end(), payload.begin(), payload.end());
    return msg;
}

std::vector<unsigned char> PopMessage(const std::vector<unsigned char>& pk)
{
    return DstMessage(nbp::DST_POP, pk);
}

std::vector<unsigned char> ExitMessage(const std::vector<unsigned char>& pk)
{
    static const std::string action{"exit"};
    std::vector<unsigned char> payload(action.begin(), action.end());
    payload.insert(payload.end(), pk.begin(), pk.end());
    return DstMessage(nbp::DST_POP, payload);
}

std::vector<unsigned char> WithdrawMessage(const std::vector<unsigned char>& pk, const CTxOut& out)
{
    static const std::string action{"withdraw"};
    std::vector<unsigned char> payload(action.begin(), action.end());
    payload.insert(payload.end(), pk.begin(), pk.end());
    uint256 scriptHash;
    CSHA256().Write(out.scriptPubKey.data(), out.scriptPubKey.size()).Finalize(scriptHash.begin());
    payload.insert(payload.end(), scriptHash.begin(), scriptHash.end());
    const uint64_t v = static_cast<uint64_t>(out.nValue);
    for (int i = 0; i < 8; i++) payload.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xff));
    return DstMessage(nbp::DST_POP, payload);
}

std::vector<unsigned char> ChallengeMessage(const uint256& depositId)
{
    static const std::string action{"challenge"};
    std::vector<unsigned char> payload(action.begin(), action.end());
    payload.insert(payload.end(), depositId.begin(), depositId.end());
    return DstMessage(nbp::DST_RES, payload);
}

uint256 ComputeClaimCommit(const blsct::DoublePublicKey& dpk, const uint256& r)
{
    const auto dpkVch = dpk.GetVch();
    uint256 out;
    CSHA256 hasher;
    hasher.Write(dpkVch.data(), dpkVch.size());
    hasher.Write(r.begin(), 32);
    hasher.Finalize(out.begin());
    return out;
}

namespace {

// --- bridge tx factory --------------------------------------------------------
//
// Mirrors TxFactoryBase::BuildTx but supports the NBP balance extensions:
//  - transparent predicate outputs (nValue under the NAV generator, no gamma);
//  - pseudo-inputs (consensus-minted value: withdraw bond, mint amount,
//    resolve refund, slash reward) which reduce the funding target;
//  - pseudo-outputs (consensus-burned value: burn amount) which raise it.
class BridgeTxFactory : public TxFactoryBase
{
private:
    //! Transparent predicate-carrying outputs. `blindingKey` is only used
    //! when the output has BLSCT keys (spendable payout outputs).
    std::vector<UnsignedOutput> bridgeOuts;
    std::map<TokenId, CAmount> pseudoInputs;
    std::map<TokenId, CAmount> pseudoOutputs;

public:
    BridgeTxFactory() = default;

    using TxFactoryBase::AddInput;
    using TxFactoryBase::AddOutput;

    void AddBridgeOutput(const UnsignedOutput& out) { bridgeOuts.push_back(out); }
    void AddPseudoInput(const TokenId& token_id, const CAmount& amount) { pseudoInputs[token_id] += amount; }
    void AddPseudoOutput(const TokenId& token_id, const CAmount& amount) { pseudoOutputs[token_id] += amount; }

    //! Attach an NBP predicate to the first hidden output of `token_id`
    //! (used by the bridge-mint builder). Must be called before Build().
    void SetPredicateOnFirstOutput(const TokenId& token_id, const VectorPredicate& predicate)
    {
        auto it = vOutputs.find(token_id);
        if (it == vOutputs.end() || it->second.empty()) {
            throw std::runtime_error("no output to attach the bridge predicate to");
        }
        it->second.front().out.predicate = predicate;
    }

    std::optional<CMutableTransaction> Build(const blsct::DoublePublicKey& changeDestination,
                                             const CAmount& nBLSCTDefaultFee)
    {
        this->tx = CMutableTransaction();

        std::vector<Signature> outputSignatures;
        MclScalar outputGammas;
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
            }
        }

        // Transparent predicate outputs: no gamma; keyed (spendable) ones
        // need the ephemeral-key signature over the output hash.
        for (auto& out : bridgeOuts) {
            this->tx.vout.push_back(out.out);
            if (out.out.HasBLSCTKeys()) {
                outputSignatures.push_back(PrivateKey(out.blindingKey).Sign(out.out.GetHash()));
            }
        }

        // Largest-value first (see TxFactoryBase::BuildTx).
        for (auto& in_ : vInputs) {
            std::sort(in_.second.begin(), in_.second.end(), [](const UnsignedInput& a, const UnsignedInput& b) {
                return a.value.GetUint64() > b.value.GetUint64();
            });
        }

        // Funding target per token:
        //   hidden outputs + transparent predicate outputs + consensus-burned
        //   value − consensus-minted value (+ fee for the native token).
        // The fee component is added inside the fixpoint loop below.
        std::set<TokenId> tokenIds;
        for (const auto& it : nAmounts) tokenIds.insert(it.first);
        for (const auto& it : vInputs) tokenIds.insert(it.first);
        for (const auto& it : pseudoInputs) tokenIds.insert(it.first);
        for (const auto& it : pseudoOutputs) tokenIds.insert(it.first);
        tokenIds.insert(TokenId());

        std::map<TokenId, CAmount> baseTarget;
        for (const auto& token_id : tokenIds) {
            CAmount target = 0;
            if (nAmounts.contains(token_id)) target += nAmounts[token_id].nFromOutputs;
            for (const auto& out : bridgeOuts) {
                if (out.out.tokenId == token_id) target += out.out.nValue;
            }
            if (pseudoOutputs.contains(token_id)) target += pseudoOutputs[token_id];
            if (pseudoInputs.contains(token_id)) target -= pseudoInputs[token_id];
            if (target < 0) {
                // Consensus mints more than this tx spends: not constructible
                // without burning the excess. All bridge tx shapes are exact.
                throw std::runtime_error("bridge tx pseudo-input exceeds its outputs");
            }
            baseTarget[token_id] = target;
        }

        while (true) {
            CMutableTransaction tx = this->tx;
            tx.nVersion |= CTransaction::BLSCT_MARKER;

            MclScalar gammaAcc = outputGammas;
            std::map<TokenId, CAmount> mapInputs;
            std::vector<Signature> txSigs = outputSignatures;

            const CAmount fee = nAmounts[TokenId()].nFromFee;

            for (auto& in_ : vInputs) {
                const CAmount target = baseTarget[in_.first] + (in_.first.IsNull() ? fee : 0);
                for (auto& in : in_.second) {
                    if (mapInputs[in_.first] >= target) break;

                    tx.vin.push_back(in.in);
                    gammaAcc = gammaAcc + in.gamma;
                    txSigs.push_back(in.sk.Sign(in.in.GetHash()));
                    mapInputs[in_.first] += in.value.GetUint64();
                }
            }

            bool insufficient = false;
            std::map<TokenId, CAmount> mapChange;
            for (const auto& token_id : tokenIds) {
                const CAmount target = baseTarget[token_id] + (token_id.IsNull() ? fee : 0);
                if (mapInputs[token_id] < target) {
                    insufficient = true;
                    break;
                }
                mapChange[token_id] = mapInputs[token_id] - target;
            }
            if (insufficient) return std::nullopt;

            for (const auto& change : mapChange) {
                if (change.second == 0) continue;

                auto changeOutput = CreateOutput(changeDestination, change.second, "Change", change.first, MclScalar::Rand(), NORMAL, 0);

                gammaAcc = gammaAcc - changeOutput.gamma;

                tx.vout.push_back(changeOutput.out);
                txSigs.push_back(PrivateKey(changeOutput.blindingKey).Sign(changeOutput.out.GetHash()));
            }

            CTxOut fee_out{fee, CScript(OP_RETURN)};
            auto feeKey = blsct::PrivateKey(MclScalar::Rand());
            fee_out.predicate = blsct::PayFeePredicate(feeKey.GetPublicKey()).GetVch();

            tx.vout.push_back(fee_out);
            txSigs.push_back(PrivateKey(gammaAcc).SignBalance());
            txSigs.push_back(feeKey.SignFee());

            tx.txSig = Signature::Aggregate(txSigs);

            const CAmount required_fee = GetTransactionWeight(CTransaction(tx)) * nBLSCTDefaultFee;
            if (fee == required_fee) {
                // Randomise ordering (see TxFactoryBase::BuildTx).
                std::seed_seq seed{MclScalar::Rand().GetUint64(), MclScalar::Rand().GetUint64(),
                                   MclScalar::Rand().GetUint64(), MclScalar::Rand().GetUint64()};
                std::mt19937_64 rng(seed);
                std::shuffle(tx.vin.begin(), tx.vin.end(), rng);
                std::shuffle(tx.vout.begin(), tx.vout.end(), rng);
                return tx;
            }
            nAmounts[TokenId()].nFromFee = required_fee;
        }
    }
};

//! An unspendable (OP_RETURN) predicate-carrying output. With nValue > 0 the
//! transparent value is serialized (TRANSPARENT_VALUE_MARKER is set whenever
//! a predicate is present) and must be funded from the tx inputs unless a
//! pseudo-input covers it.
UnsignedOutput CreateOpReturnPredicateOutput(const VectorPredicate& predicate, const CAmount& nValue = 0)
{
    UnsignedOutput ret;
    ret.out.nValue = nValue;
    ret.out.scriptPubKey = CScript(OP_RETURN);
    ret.out.predicate = predicate;
    ret.value = nValue;
    return ret;
}

//! A spendable transparent output owned by `destKeys` (same shape as NFT
//! outputs: BLSCT keys + view tag, plaintext nValue, no range proof). The
//! predicate must be attached by the caller BEFORE any signature over the
//! output hash is computed; note the TRANSPARENT_VALUE_MARKER only carries
//! nValue when a predicate is present, which is always the case here.
UnsignedOutput CreateSpendablePredicateOutput(const blsct::DoublePublicKey& destKeys, const CAmount& nValue)
{
    UnsignedOutput ret;
    ret.type = NORMAL;
    ret.out.nValue = nValue;
    ret.out.scriptPubKey = CScript(OP_TRUE);
    ret.blindingKey = MclScalar::Rand();
    ret.value = nValue;
    ret.gamma = MclScalar(); // transparent value: no commitment, no gamma

    ret.GenerateKeys(ret.blindingKey, destKeys);

    MclG1Point vk;
    if (!destKeys.GetViewKey(vk)) {
        throw std::runtime_error("could not get view key from destination address");
    }
    auto nonce = vk * ret.blindingKey;
    HashWriter hash{};
    hash << nonce;
    ret.out.blsctData.viewTag = (hash.GetHash().GetUint64(0) & 0xFFFF);

    return ret;
}

//! Gather spendable coins and feed them into the factory (skipping staked
//! commitments — bridge txs never touch the stake).
void AddCoins(BridgeTxFactory& factory, wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
              const TokenId& token_id, const CAmount& nAmountLimit)
    EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet)
{
    std::vector<InputCandidates> inputCandidates;
    TxFactory::AddAvailableCoins(wallet, blsct_km, token_id, CreateTransactionType::NORMAL,
                                 inputCandidates, nAmountLimit);
    for (const auto& candidate : inputCandidates) {
        if (candidate.is_staked_commitment) continue;
        factory.AddInput(candidate.amount, candidate.gamma, candidate.spendingKey,
                         candidate.token_id, candidate.outpoint);
    }
}

blsct::DoublePublicKey GetChangeDestination(blsct::KeyMan* blsct_km)
{
    auto dest = blsct_km->GetNewDestination(CHANGE_ACCOUNT);
    if (!dest) throw std::runtime_error("could not derive a change address");
    return std::get<blsct::DoublePublicKey>(dest.value());
}

CAmount FeeRate()
{
    return Params().GetConsensus().nBLSCTDefaultFee;
}

//! Rough upper bound for fee funding of the fee-only bridge txs.
constexpr CAmount FEE_FUNDING_LIMIT{COIN};

} // namespace

// --- builders -----------------------------------------------------------------

std::optional<CMutableTransaction> BuildGuardianRegisterTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const CAmount& bond, uint32_t sppRefHeight)
{
    LOCK(wallet->cs_wallet);

    const auto guardianKey = GetGuardianKey(blsct_km);
    const auto pk = guardianKey.GetPublicKey();

    nbp::GuardianRegisterPredicate predicate;
    predicate.guardianKey = pk;
    predicate.proofOfPossession = guardianKey.Sign(PopMessage(pk.GetVch()));
    predicate.sppBlob = {0x01}; // mock SPP (IMPLEMENTATION.md P1)
    predicate.sppRefHeight = sppRefHeight;

    BridgeTxFactory factory;
    factory.AddBridgeOutput(CreateOpReturnPredicateOutput(
        NbpPredicateToVch(NBP_GUARDIAN_REGISTER, predicate), bond));
    AddCoins(factory, wallet, blsct_km, TokenId(), bond + FEE_FUNDING_LIMIT);

    return factory.Build(GetChangeDestination(blsct_km), FeeRate());
}

std::optional<CMutableTransaction> BuildGuardianExitTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km)
{
    LOCK(wallet->cs_wallet);

    const auto guardianKey = GetGuardianKey(blsct_km);
    const auto pk = guardianKey.GetPublicKey();

    nbp::GuardianExitPredicate predicate;
    predicate.guardianKey = pk;
    predicate.exitSig = guardianKey.Sign(ExitMessage(pk.GetVch()));

    BridgeTxFactory factory;
    factory.AddBridgeOutput(CreateOpReturnPredicateOutput(
        NbpPredicateToVch(NBP_GUARDIAN_EXIT, predicate)));
    AddCoins(factory, wallet, blsct_km, TokenId(), FEE_FUNDING_LIMIT);

    return factory.Build(GetChangeDestination(blsct_km), FeeRate());
}

std::optional<CMutableTransaction> BuildGuardianWithdrawTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const CAmount& bond)
{
    LOCK(wallet->cs_wallet);

    const auto guardianKey = GetGuardianKey(blsct_km);
    const auto pk = guardianKey.GetPublicKey();

    auto out = CreateSpendablePredicateOutput(GetClaimDestination(blsct_km), bond);

    nbp::GuardianWithdrawPredicate predicate;
    predicate.guardianKey = pk;
    // Binds script hash + value; independent of the predicate itself.
    predicate.withdrawSig = guardianKey.Sign(WithdrawMessage(pk.GetVch(), out.out));
    out.out.predicate = NbpPredicateToVch(NBP_GUARDIAN_WITHDRAW, predicate);

    BridgeTxFactory factory;
    factory.AddBridgeOutput(out);
    factory.AddPseudoInput(TokenId(), bond); // consensus mints the bond back
    AddCoins(factory, wallet, blsct_km, TokenId(), FEE_FUNDING_LIMIT);

    return factory.Build(GetChangeDestination(blsct_km), FeeRate());
}

std::optional<CMutableTransaction> BuildBridgeMintTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
    uint64_t ethChainId, const std::vector<unsigned char>& token,
    const uint256& depositId, const CAmount& amount, const uint256& r,
    const std::vector<unsigned char>& bitfield, const blsct::Signature& aggSig)
{
    LOCK(wallet->cs_wallet);

    const auto dpk = GetClaimDestination(blsct_km);
    const TokenId tokenId{nbp::BridgeTokenId(ethChainId, token)};

    nbp::BridgeMintPredicate predicate;
    predicate.ethChainId = ethChainId;
    predicate.token = token;
    predicate.depositId = depositId;
    predicate.amount = amount;
    predicate.dpk = dpk;
    predicate.r = r;
    predicate.claimCommit = ComputeClaimCommit(dpk, r);
    predicate.bitfield = bitfield;
    predicate.aggSig = aggSig;

    BridgeTxFactory factory;
    // The confidential wrapped-token output; consensus's pseudo-input forces
    // the hidden outputs to sum to exactly `amount` under the token generator.
    factory.AddOutput(SubAddress(dpk), amount, "NBP claim", tokenId);
    factory.SetPredicateOnFirstOutput(tokenId, NbpPredicateToVch(NBP_BRIDGE_MINT, predicate));
    factory.AddPseudoInput(tokenId, amount);
    AddCoins(factory, wallet, blsct_km, TokenId(), FEE_FUNDING_LIMIT);

    return factory.Build(GetChangeDestination(blsct_km), FeeRate());
}

std::optional<CMutableTransaction> BuildBridgeBurnTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
    uint64_t ethChainId, const std::vector<unsigned char>& token,
    const CAmount& amount, const std::vector<unsigned char>& ethRecipient)
{
    LOCK(wallet->cs_wallet);

    const TokenId tokenId{nbp::BridgeTokenId(ethChainId, token)};

    nbp::BridgeBurnPredicate predicate;
    predicate.ethChainId = ethChainId;
    predicate.token = token;
    predicate.amount = amount;
    predicate.ethRecipient = ethRecipient;

    BridgeTxFactory factory;
    factory.AddBridgeOutput(CreateOpReturnPredicateOutput(
        NbpPredicateToVch(NBP_BRIDGE_BURN, predicate)));
    // Hidden token inputs must exceed the burned amount; the surplus comes
    // back as hidden token change.
    factory.AddPseudoOutput(tokenId, amount);
    // Wrapped-token coins to cover the burn, plus NAV coins for the fee.
    AddCoins(factory, wallet, blsct_km, tokenId, amount);
    AddCoins(factory, wallet, blsct_km, TokenId(), FEE_FUNDING_LIMIT);

    return factory.Build(GetChangeDestination(blsct_km), FeeRate());
}

std::optional<CMutableTransaction> BuildChallengeTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
    const uint256& depositId, const CAmount& challengeBond)
{
    LOCK(wallet->cs_wallet);

    const auto guardianKey = GetGuardianKey(blsct_km);

    nbp::BridgeChallengePredicate predicate;
    predicate.depositId = depositId;
    predicate.guardianKey = guardianKey.GetPublicKey();
    predicate.challengeSig = guardianKey.Sign(ChallengeMessage(depositId));

    BridgeTxFactory factory;
    factory.AddBridgeOutput(CreateOpReturnPredicateOutput(
        NbpPredicateToVch(NBP_BRIDGE_CHALLENGE, predicate), challengeBond));
    AddCoins(factory, wallet, blsct_km, TokenId(), challengeBond + FEE_FUNDING_LIMIT);

    return factory.Build(GetChangeDestination(blsct_km), FeeRate());
}

std::optional<CMutableTransaction> BuildResolveTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
    const uint256& depositId, const uint256& challengeTxid, uint8_t verdict,
    const std::vector<unsigned char>& bitfield, const blsct::Signature& aggSig,
    const CAmount& refundAmount)
{
    LOCK(wallet->cs_wallet);

    nbp::BridgeResolvePredicate predicate;
    predicate.challengeTxid = challengeTxid;
    predicate.depositId = depositId;
    predicate.verdict = verdict;
    predicate.bitfield = bitfield;
    predicate.aggSig = aggSig;

    const auto predicateVch = NbpPredicateToVch(NBP_BRIDGE_RESOLVE, predicate);

    BridgeTxFactory factory;
    if (verdict == 1) {
        // Challenge upheld: consensus mints challengeBond + totalSlashed/10
        // into the carrying output.
        auto out = CreateSpendablePredicateOutput(GetClaimDestination(blsct_km), refundAmount);
        out.out.predicate = predicateVch;
        factory.AddBridgeOutput(out);
        factory.AddPseudoInput(TokenId(), refundAmount);
    } else {
        factory.AddBridgeOutput(CreateOpReturnPredicateOutput(predicateVch));
    }
    AddCoins(factory, wallet, blsct_km, TokenId(), FEE_FUNDING_LIMIT);

    return factory.Build(GetChangeDestination(blsct_km), FeeRate());
}

std::optional<CMutableTransaction> BuildSlashTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
    uint8_t evidenceType, const blsct::PublicKey& guardianKey,
    const std::vector<unsigned char>& msg1, const blsct::Signature& sig1,
    const std::vector<unsigned char>& msg2, const blsct::Signature& sig2,
    const CAmount& rewardAmount)
{
    LOCK(wallet->cs_wallet);

    nbp::GuardianSlashPredicate predicate;
    predicate.evidenceType = evidenceType;
    predicate.guardianKey = guardianKey;
    predicate.msg1 = msg1;
    predicate.sig1 = sig1;
    predicate.msg2 = msg2;
    predicate.sig2 = sig2;

    auto out = CreateSpendablePredicateOutput(GetClaimDestination(blsct_km), rewardAmount);
    out.out.predicate = NbpPredicateToVch(NBP_GUARDIAN_SLASH, predicate);

    BridgeTxFactory factory;
    factory.AddBridgeOutput(out);
    factory.AddPseudoInput(TokenId(), rewardAmount); // consensus-minted reporter reward
    AddCoins(factory, wallet, blsct_km, TokenId(), FEE_FUNDING_LIMIT);

    return factory.Build(GetChangeDestination(blsct_km), FeeRate());
}

} // namespace bridge
} // namespace blsct
