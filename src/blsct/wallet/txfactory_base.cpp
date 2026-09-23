// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory_base.h>
#include <consensus/amount.h>
#include <tinyformat.h>
#include <util/rbf.h>

#include <random>

using T = Blst;
using Point = T::Point;
using Points = Elements<Point>;
using Scalar = T::Scalar;
using Scalars = Elements<Scalar>;

namespace blsct {

namespace {
// Backstop for the fee fixpoint in BuildTx(). The loop terminates on its own:
// the assumed fee never decreases and every non-accepting pass raises it
// strictly (see the comment at the acceptance test), so it cannot cycle. This
// cap only ensures that a future change breaking that argument fails loudly
// instead of spinning forever inside the loop -- BuildTx runs under
// cs_wallet, so a spin wedges the whole wallet until the process is killed.
//
// Sized off the input cap rather than picked round: a raised fee only forces
// another pass by pulling in more inputs, of which there can be at most
// MAX_TX_INPUT_COUNT, the change output can appear or disappear once at each
// input count, and one further pass accepts.
constexpr size_t MAX_FEE_FIXPOINT_PASSES = 2 * MAX_TX_INPUT_COUNT + 2;

std::runtime_error TooManyInputsError()
{
    return std::runtime_error(strprintf(
        "This transaction would need more than %u inputs (too many small outputs to spend at once). "
        "Consolidate small outputs first with the 'consolidate' RPC, then retry.",
        MAX_TX_INPUT_COUNT));
}
} // namespace

Scalar TxFactoryBase::BlindingKeyFor(const std::optional<Scalar>& pinned, const uint32_t ordinal, const std::optional<Outid>& anchor) const
{
    // An explicitly supplied key always wins: that is the documented opt-out
    // for callers that want an unrecoverable random scalar (or that are
    // replaying a key they already committed to).
    if (pinned) return *pinned;

    // No wallet seed (raw/offline builders, most unit tests) or no input to
    // anchor on (a factory with no inputs at all). Fall back to the old
    // behaviour: a random, unrecoverable key.
    if (!m_blinding_seed || !anchor) return Scalar::Rand();

    // The generation makes repeated builds over the same input set derive
    // different scalars. Without a source for it there is no way to know
    // whether this anchor has been built on before, and deriving anyway would
    // risk reusing a scalar for a different amount -- which reuses the range
    // proof's entire randomness. A random key loses recoverability; a reused
    // one loses the amount. Take the random one.
    if (!m_blinding_generation_fn) return Scalar::Rand();

    auto claimed = m_claimed_generations.find(*anchor);
    if (claimed == m_claimed_generations.end()) {
        const auto generation = m_blinding_generation_fn(*anchor);
        if (!generation) return Scalar::Rand();
        claimed = m_claimed_generations.emplace(*anchor, *generation).first;
    }

    return DeriveBlindingKey(*m_blinding_seed, *anchor, ordinal, claimed->second);
}

std::optional<Outid> TxFactoryBase::CanonicalAnchorOf(const std::vector<const UnsignedInput*>& selected)
{
    std::vector<COutPoint> outpoints;
    outpoints.reserve(selected.size());
    for (const UnsignedInput* in : selected) outpoints.push_back(in->in.prevout);
    return CanonicalAnchor(outpoints);
}

std::optional<Outid> TxFactoryBase::CanonicalAnchorOfAllInputs() const
{
    std::vector<COutPoint> outpoints;
    for (const auto& in_ : vInputs) {
        for (const auto& in : in_.second) outpoints.push_back(in.in.prevout);
    }
    return CanonicalAnchor(outpoints);
}

void TxFactoryBase::AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id, const CreateTransactionType& type, const CAmount& minStake, const bool& fSubtractFeeFromAmount, const std::optional<Scalar>& blindingKey, const CAmount& nBLSCTDefaultFee, const std::optional<delegation::DelegationRequest>& stakeDelegation)
{
    // Reject before touching nAmounts: a non-positive or out-of-range value
    // would otherwise be folded into the per-token totals and surface only
    // later as an unexplained consensus rejection of the built transaction.
    if (nAmount <= 0 || !MoneyRange(nAmount)) {
        throw std::runtime_error(strprintf("%s: amount must be positive and within the money range (got %d)", __func__, nAmount));
    }

    if (!nAmounts.contains(token_id))
        nAmounts[token_id] = {0, 0, 0};

    // The sender-assigned ordinal this output's blinding scalar is keyed on.
    // Taken here, in AddOutput order, so it is stable no matter how BuildTx
    // later orders or shuffles vout.
    const uint32_t ordinal = m_next_output_ordinal++;

    if (fSubtractFeeFromAmount) {
        // The final value is (nAmount - total transaction fee), and the total
        // fee is only known once BuildTx's fee fixpoint converges. Defer the
        // output; BuildTx materializes it at the reduced value. Reuse the
        // supplied blindingKey (and, when derived, the ordinal) across
        // rebuilds so the deferral is deterministic.
        subtractFeeOutput = SubtractFeeOutput{destination, nAmount, sMemo, token_id, type, minStake, blindingKey, ordinal};
        return;
    }

    // Queue rather than build. The blinding scalar is derived from an input
    // outpoint, so the output cannot be materialized until BuildTx has settled
    // coin selection; see PendingOutput in the header.
    nAmounts[token_id].nFromOutputs += nAmount;
    vPendingOutputs.push_back(PendingOutput{destination, nAmount, std::move(sMemo), token_id, type, minStake, blindingKey, stakeDelegation, ordinal});
}

UnsignedOutput TxFactoryBase::MaterializeOutput(const PendingOutput& pending, const std::optional<Outid>& anchor) const
{
    const Scalar blindingKey = BlindingKeyFor(pending.blindingKey, pending.ordinal, anchor);

    UnsignedOutput out = CreateOutput(pending.destination.GetKeys(), pending.amount, pending.memo, pending.token_id, blindingKey, pending.type, pending.minStake, /*fAllowZeroValueRangeProof=*/false, m_transcript_v2);

    if (pending.stakeDelegation.has_value() && pending.type == STAKED_COMMITMENT && pending.token_id.IsNull()) {
        // Attach the encrypted opening of the just-built commitment so the
        // delegate can stake it. DATA predicates are consensus no-ops, and
        // the predicate is set before BuildTx() computes the output
        // signatures, so the payload is covered by the ownership signature.
        // Delegated stakes never take the subtract-fee path above, so the
        // committed value is exactly the queued amount.
        // The owner section is keyed on the output's BLSCT nonce, letting the
        // owner wallet re-derive its delegations from the chain alone.
        delegation::DelegationInfo info;
        info.value = pending.amount;
        info.gamma = out.gamma;
        info.rewardAddress = pending.stakeDelegation->rewardAddress;
        Point vk;
        if (!pending.destination.GetKeys().GetViewKey(vk)) {
            throw std::runtime_error(std::string(__func__) + ": could not get view key from stake destination");
        }
        const Point nonce = vk * out.blindingKey;
        out.out.predicate = DataPredicate(delegation::Encrypt(info, *pending.stakeDelegation, nonce)).GetVch();
    }

    return out;
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

    out = CreateOutput(destination.GetKeys(), mintAmount, Scalar::Rand(), tokenKey, tokenPublicKey, m_transcript_v2);

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

std::optional<BuiltTransaction>
TxFactoryBase::BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake, const CreateTransactionType& type, const bool& fSubtractedFee, const CAmount& nBLSCTDefaultFee, const CAmount& additionalFee, const bool& emitFeeOutput)
{
    this->tx = CMutableTransaction();

    std::vector<Signature> outputSignatures;
    Scalar outputGammas;
    nAmounts[TokenId()].nFromFee = 0;

    // Select largest-value inputs first. The loops below add inputs in order
    // until the target is covered, so without this a wallet full of small
    // outputs (e.g. PoS staking rewards) would pile in many tiny inputs and
    // produce an oversized BLSCT transaction. Sorting descending keeps the
    // input count -- and therefore the tx size -- minimal.
    //
    // This runs BEFORE the outputs are materialized, which is the opposite of
    // the pre-recoverable-blinding-key order: the blinding scalar of every
    // output is derived from the transaction's anchor input, so coin
    // selection has to be settled first. Sorting has no dependency on the
    // outputs, so moving it up is order-neutral for everything else.
    for (auto& in_ : vInputs) {
        std::sort(in_.second.begin(), in_.second.end(), [](const UnsignedInput& a, const UnsignedInput& b) {
            return a.value.GetUint64() > b.value.GetUint64();
        });
    }

    // Blinding scalars of the outputs built here, keyed by output hash, for
    // the wallet to persist as the fast path of `signblsctoutput`. Change and
    // subtract-fee outputs are added per pass below, since they are rebuilt
    // as the fee moves.
    std::map<uint256, Scalar> baseBlindingKeys;

    // Deferred, anchor-dependent output materialization.
    //
    // Each pass selects its inputs first, takes the canonical anchor over
    // them, and only then builds the outputs. Materialization is memoized on
    // that anchor because range proofs dominate the cost of a build and the
    // anchor is stable across the fixpoint in every ordinary case, so the
    // common path pays for them exactly once.
    //
    // Rebuilding is safe when the anchor does move: BLSCT output size is
    // independent of both the value and the blinding key, so the transaction
    // weight -- and therefore the required fee the fixpoint is chasing -- does
    // not change.
    std::optional<Outid> builtAnchor;
    bool materialized = false;

    auto materialize = [&](const std::optional<Outid>& anchor) {
        this->tx.vout.clear();
        outputSignatures.clear();
        outputGammas = Scalar();
        baseBlindingKeys.clear();

        // The queued transfer outputs, then any token create/mint outputs,
        // which carry no destination blinding key of ours and are built
        // eagerly by their AddOutput overloads.
        std::vector<UnsignedOutput> builtOutputs;
        builtOutputs.reserve(vPendingOutputs.size());
        for (const auto& pending : vPendingOutputs) {
            builtOutputs.push_back(MaterializeOutput(pending, anchor));
        }
        for (auto& out_ : vOutputs) {
            for (auto& out : out_.second) builtOutputs.push_back(out);
        }

        for (auto& out : builtOutputs) {
            this->tx.vout.push_back(out.out);
            auto outHash = out.out.GetHash();

            if (out.out.HasBLSCTRangeProof()) {
                outputGammas = outputGammas - out.gamma;
            }
            if (out.out.HasBLSCTKeys()) {
                outputSignatures.push_back(PrivateKey(out.blindingKey).Sign(outHash));
                baseBlindingKeys[outHash] = out.blindingKey;
            }

            if (out.type == TX_CREATE_TOKEN || out.type == TX_MINT_TOKEN) {
                outputSignatures.push_back(PrivateKey(out.tokenKey).Sign(outHash));
            }
        }

        builtAnchor = anchor;
        materialized = true;
    };

    const auto same_anchor = [](const std::optional<Outid>& a, const std::optional<Outid>& b) {
        if (a.has_value() != b.has_value()) return false;
        return !a.has_value() || a->ToUint256() == b->ToUint256();
    };

    // What the ordinary (non-deferred) outputs of the deferred recipient's
    // token contribute. The deferred output is re-materialized on every pass
    // at a value that depends on the current fee estimate, so its token's
    // total has to be rebuilt from this each time rather than accumulated.
    const CAmount nFromPlainOutputs = subtractFeeOutput ? nAmounts[subtractFeeOutput->token_id].nFromOutputs : 0;

    for (size_t pass = 0; pass < MAX_FEE_FIXPOINT_PASSES; ++pass) {
        std::map<TokenId, CAmount> mapChange;
        std::map<TokenId, CAmount> mapInputs;
        // Set if selection stops because the per-tx input cap is reached while
        // funds remain unselected -- i.e. the amount needs more inputs than fit
        // in one transaction. Distinguishes "consolidate first" from genuine
        // insufficient funds below.
        bool hitInputCap = false;

        // Settle the deferred subtract-fee-from-amount recipient's VALUE at
        // (amount - current fee estimate). BLSCT output size is
        // value-independent, so lowering the value does not change the fee and
        // the fixpoint still converges (typically in two passes). Setting
        // nFromOutputs to the reduced value makes input selection target the
        // original amount (reduced + fee), so the fee is routed out of the
        // recipient output rather than out of change. Any ordinary output of
        // the same token is still owed in full, hence the sum rather than a
        // plain assignment.
        //
        // Only the value is settled here; the output itself is built further
        // down, once the anchor its blinding key derives from is known.
        std::optional<CAmount> sffaReduced;
        if (subtractFeeOutput) {
            const CAmount fee = nAmounts[TokenId()].nFromFee;
            const CAmount reduced = subtractFeeOutput->amount - fee;
            if (reduced < 0) return std::nullopt; // fee exceeds the amount sent
            nAmounts[subtractFeeOutput->token_id].nFromOutputs = nFromPlainOutputs + reduced;
            sffaReduced = reduced;
        }

        // Coin selection. It reads only the per-token amount totals, which
        // AddOutput accumulated, so it has no dependency on the outputs and
        // can run before they exist. The chosen inputs are collected rather
        // than pushed straight into a transaction because the anchor -- and
        // through it every output -- is a function of this set.
        std::vector<const UnsignedInput*> selected;
        if (type == STAKED_COMMITMENT_UNSTAKE || type == STAKED_COMMITMENT) {
            // Consume EVERY staked input the caller added: CreateTransaction
            // already selected exactly which commitments this transaction
            // spends and sized the staked output (new stake or unstake
            // change) assuming all of them are consumed. Capping selection
            // here (the previous `mapInputs > nFromOutputs` break) broke that
            // assumption for multi-commitment stakes: a full unstake consumed
            // only the first commitment, and a partial unstake backfilled the
            // remainder of the staked change from spendable coins — silently
            // re-staking funds the user never asked to stake.
            for (auto& in_ : vInputs) {
                for (auto& in : in_.second) {
                    if (!in.is_staked_commitment) continue;
                    if (!mapInputs[in_.first]) mapInputs[in_.first] = 0;

                    selected.push_back(&in);
                    mapInputs[in_.first] += in.value.GetUint64();
                }
            }
        }
        for (auto& in_ : vInputs) {
            for (auto& in : in_.second) {
                if (in.is_staked_commitment) continue;
                if (!mapInputs[in_.first]) mapInputs[in_.first] = 0;
                if (mapInputs[in_.first] > nAmounts[in_.first].nFromOutputs + nAmounts[in_.first].nFromFee) break;
                if (selected.size() >= MAX_TX_INPUT_COUNT) {
                    hitInputCap = true;
                    break;
                }

                selected.push_back(&in);
                mapInputs[in_.first] += in.value.GetUint64();
            }
            if (hitInputCap) break;
        }

        // The anchor every blinding scalar in this transaction derives from:
        // the canonically smallest outid among the inputs just selected.
        //
        // Taken from the SELECTED set, not from everything the factory holds,
        // so the anchor is guaranteed to survive into the built transaction --
        // deriving from an input coin selection then drops would leave the
        // outputs unrecoverable. It is also stable once chosen: raising the
        // fee only ever lengthens the prefix of the value-sorted inputs that
        // selection takes (and for a subtract-fee send the target
        // `reduced + fee` is constant), so the selected set grows
        // monotonically across passes and an earlier anchor stays in it.
        const std::optional<Outid> anchor = CanonicalAnchorOf(selected);
        if (!materialized || !same_anchor(builtAnchor, anchor)) materialize(anchor);

        CMutableTransaction tx = this->tx;
        tx.nVersion |= CTransaction::BLSCT_MARKER;
        // Stamp the proof-v2 marker when the outputs are built under the v2
        // transcript, so verifiers select v2 and the flag-enforcement check
        // passes at/above the activation height.
        if (m_transcript_v2)
            tx.nVersion |= CTransaction::BLSCT_PROOF_V2_MARKER;

        Scalar gammaAcc = outputGammas;
        std::vector<Signature> txSigs = outputSignatures;
        std::map<uint256, Scalar> blindingKeys = baseBlindingKeys;

        for (const UnsignedInput* in : selected) {
            tx.vin.push_back(in->in);
            gammaAcc = gammaAcc + in->gamma;
            txSigs.push_back(in->sk.Sign(in->in.GetHash()));
        }

        std::optional<UnsignedOutput> sffaOut;
        if (sffaReduced) {
            // The ordinal is fixed at AddOutput time and the anchor is stable,
            // so the derived key is the same on every pass even though the
            // output is rebuilt at a new value.
            const Scalar sffaBlindingKey = BlindingKeyFor(subtractFeeOutput->blindingKey, subtractFeeOutput->ordinal, anchor);
            sffaOut = CreateOutput(subtractFeeOutput->destination.GetKeys(), *sffaReduced,
                                   subtractFeeOutput->memo, subtractFeeOutput->token_id,
                                   sffaBlindingKey, subtractFeeOutput->type,
                                   subtractFeeOutput->minStake, /*fAllowZeroValueRangeProof=*/false,
                                   m_transcript_v2);
            gammaAcc = gammaAcc - sffaOut->gamma;
        }

        for (auto& amounts : nAmounts) {
            auto tokenFee = nAmounts[amounts.first].nFromFee;

            auto nFromInputs = mapInputs[amounts.first];

            if (nFromInputs < amounts.second.nFromOutputs + tokenFee) {
                if (hitInputCap) {
                    throw TooManyInputsError();
                }
                return std::nullopt;
            }

            mapChange[amounts.first] = nFromInputs - amounts.second.nFromOutputs - tokenFee;
        }
        std::optional<uint256> firstChangeOutputHash;
        // Change outputs continue the sender's ordinal sequence after
        // everything AddOutput queued. Their count can move between passes (a
        // change output that lands on zero is dropped), which is harmless:
        // only the accepting pass is returned, and recovery tries every
        // ordinal anyway.
        uint32_t changeOrdinal = m_next_output_ordinal;
        for (auto& change : mapChange) {
            if (change.second == 0) continue;

            // For unstake txs the "change" output IS the unlocked portion
            // returning to the user — label it accordingly so clients (and
            // listtransactions memo field) can distinguish it from ordinary
            // change.
            const std::string change_memo = (type == STAKED_COMMITMENT_UNSTAKE)
                ? std::string{"Stake Unlock"}
                : std::string{"Change"};
            const Scalar changeBlindingKey = BlindingKeyFor(std::nullopt, changeOrdinal++, anchor);
            auto changeOutput = CreateOutput(changeDestination, change.second, change_memo, change.first, changeBlindingKey, NORMAL, minStake, /*fAllowZeroValueRangeProof=*/false, m_transcript_v2);

            gammaAcc = gammaAcc - changeOutput.gamma;

            tx.vout.push_back(changeOutput.out);
            txSigs.push_back(PrivateKey(changeOutput.blindingKey).Sign(changeOutput.out.GetHash()));
            blindingKeys[changeOutput.out.GetHash()] = changeOutput.blindingKey;

            if (!firstChangeOutputHash) firstChangeOutputHash = changeOutput.out.GetHash();
        }
        if (sffaOut) {
            tx.vout.push_back(sffaOut->out);
            txSigs.push_back(PrivateKey(sffaOut->blindingKey).Sign(sffaOut->out.GetHash()));
            blindingKeys[sffaOut->out.GetHash()] = sffaOut->blindingKey;
        }

        // Which output pays the destination this transaction was built for.
        // The vout order is randomised on the way out, so record it here while
        // the build order is still known:
        //  - a subtract-fee-from-amount send pays through sffaOut, which is
        //    appended after the change output rather than first;
        //  - otherwise it is the first output AddOutput queued, i.e. what
        //    pre-shuffle vout[0] used to be;
        //  - a full unstake queues no output at all -- the unlocked funds come
        //    back as the "Stake Unlock" change output -- so fall back to the
        //    first change output of this pass.
        // The fee output is appended after all three and is never a candidate.
        std::optional<uint256> recipientOutputHash;
        if (sffaOut) {
            recipientOutputHash = sffaOut->out.GetHash();
        } else if (!this->tx.vout.empty()) {
            recipientOutputHash = this->tx.vout[0].GetHash();
        } else {
            recipientOutputHash = firstChangeOutputHash;
        }

        // The balance signature is always required; the fee output and its
        // signature are emitted only for a normal (fee-bearing) transaction.
        txSigs.push_back(PrivateKey(gammaAcc).SignBalance());

        CAmount required_fee = 0;
        if (emitFeeOutput) {
            CTxOut fee_out{nAmounts[TokenId()].nFromFee, CScript(OP_RETURN)};

            auto feeKey = blsct::PrivateKey(BlstScalar::Rand());
            fee_out.predicate = blsct::PayFeePredicate(feeKey.GetPublicKey()).GetVch();

            tx.vout.push_back(fee_out);
            txSigs.push_back(PrivateKey(feeKey).SignFee());

            required_fee = GetTransactionWeight(CTransaction(tx)) * nBLSCTDefaultFee + additionalFee;
        }
        // A candidate half (emitFeeOutput=false) carries no fee output and no
        // fee signature: it is a value-balanced self-spend, so required_fee
        // stays 0 and the fixpoint accepts on the first pass. This is what lets
        // CombineHalves produce an aggregate with a single fee output.

        tx.txSig = Signature::Aggregate(txSigs);

        // The consensus rule is a floor, not an equality: VerifyTxCore rejects
        // only `nFee < GetTransactionWeight(tx) * nBLSCTDefaultFee`, so a
        // transaction paying more than the requirement is valid (and a higher
        // fee only helps relay). Accepting on ">=" instead of "==" -- and
        // never lowering the fee once raised -- makes the assumed fee strictly
        // increasing across non-accepting passes, which is what makes this
        // loop terminate.
        //
        // The exact-equality form could not terminate: dropping a change
        // output that lands on zero (see the `change.second == 0` skip above)
        // shrinks the transaction, so the fee required without change is lower
        // than the fee required with it. When inputs - outputs equals the
        // with-change fee exactly, the two fees chase each other forever and
        // the wallet spins under cs_wallet until it is killed. In that corner
        // this settles instead on the with-change fee while the emitted
        // (change-less) transaction only requires the smaller one: it
        // overpays by one change output's worth of weight. That trade is
        // deliberate -- a few hundred navoshis in a corner case, against a
        // wedged wallet.
        if (nAmounts[TokenId()].nFromFee >= required_fee) {
            // Every output was consumed by the fee, so there is no output to
            // hand back as the payment. Nothing builds that shape today; fail
            // rather than return a handle that points at the fee output.
            if (!recipientOutputHash) return std::nullopt;

            // Randomise input and output ordering so the on-chain transaction
            // does not leak the wallet's coin-selection order (e.g. that earlier
            // inputs correspond to larger outputs, or the change position). The
            // BLSCT aggregate signature and balance proof are order-independent,
            // so reordering does not affect validity. Seed a PRNG from BLSCT's
            // secure randomness (BlstScalar::Rand) rather than FastRandomContext,
            // which lives outside the libblsct library this file is built into.
            std::seed_seq seed{BlstScalar::Rand().GetUint64(), BlstScalar::Rand().GetUint64(),
                               BlstScalar::Rand().GetUint64(), BlstScalar::Rand().GetUint64()};
            std::mt19937_64 rng(seed);
            std::shuffle(tx.vin.begin(), tx.vin.end(), rng);
            std::shuffle(tx.vout.begin(), tx.vout.end(), rng);
            // The shuffle is why the anchor is canonical rather than
            // positional: the input the blinding keys were derived from is no
            // longer at a known position here, let alone after block
            // aggregation merges this vin with every other transaction's in
            // the block. Its identity as the smallest outid of the sender's
            // own input set survives both. See blsct::CanonicalAnchor.
            return BuiltTransaction{tx, *recipientOutputHash, std::move(blindingKeys)};
        }
        // Only reached with required_fee > nFromFee, so this raises the fee.
        nAmounts[TokenId()].nFromFee = required_fee;
    }

    throw std::runtime_error(strprintf(
        "The transaction fee did not settle after %u passes. This is a bug in the "
        "wallet's fee calculation; please report it along with the amount sent and "
        "the number of inputs the wallet holds.",
        MAX_FEE_FIXPOINT_PASSES));
}

bool TxFactoryBase::AddInput(const CAmount& amount, const BlstScalar& gamma, const PrivateKey& spendingKey, const TokenId& token_id, const COutPoint& outpoint, const bool& stakedCommitment, const bool& rbf)
{
    if (!vInputs.contains(token_id))
        vInputs[token_id] = std::vector<UnsignedInput>();

    // NOLINTNEXTLINE(modernize-use-emplace) UnsignedInput is an aggregate; parenthesized emplace_back is not portable across libstdc++/libc++.
    vInputs[token_id].push_back({CTxIn(outpoint, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL), amount, gamma, spendingKey, stakedCommitment});

    if (!nAmounts.contains(token_id))
        nAmounts[token_id] = {0, 0, 0};

    nAmounts[token_id].nFromInputs += amount;

    return true;
}

size_t TxFactoryBase::InputCount() const
{
    size_t n = 0;
    for (const auto& [token_id, inputs] : vInputs) n += inputs.size();
    return n;
}

std::optional<CMutableTransaction> TxFactoryBase::BuildHalfAddingSpares(
    const std::vector<InputCandidates>& spares,
    size_t first_spare,
    const std::function<std::optional<CMutableTransaction>()>& build)
{
    // A half spends every input this factory holds (BuildUnbalancedHalf has no
    // cap of its own), so enforce MAX_TX_INPUT_COUNT here: refuse a factory
    // already past it, and fail rather than add a spare that would pass it.
    if (InputCount() > MAX_TX_INPUT_COUNT) throw TooManyInputsError();
    auto half = build();
    for (size_t i = first_spare; !half && i < spares.size(); ++i) {
        if (InputCount() >= MAX_TX_INPUT_COUNT) throw TooManyInputsError();
        const auto& c = spares[i];
        AddInput(c.amount, c.gamma, c.spendingKey, c.token_id, COutPoint(c.outpoint.hash), c.is_staked_commitment);
        half = build();
    }
    return half;
}

std::optional<CMutableTransaction>
TxFactoryBase::BuildUnbalancedHalf(const blsct::DoublePublicKey& changeDestination,
                                   const SubAddress& recvDestination,
                                   const TokenId& pay_token,
                                   const CAmount& pay_amount,
                                   const TokenId& recv_token,
                                   const CAmount& recv_amount,
                                   const CAmount& nBLSCTDefaultFee,
                                   const CAmount& additionalFee)
{
    // Output the received token up front; its blinding/gamma are folded into the
    // balance accumulator so the half's signature covers it. There is no matching
    // input for recv_token here — the counterparty's half supplies it.
    auto recvOutput = CreateOutput(recvDestination.GetKeys(), recv_amount, "swap-recv", recv_token, Scalar::Rand(), NORMAL, 0, /*fAllowZeroValueRangeProof=*/false, m_transcript_v2);

    // A half spends every input it holds unconditionally, so the canonical
    // anchor over all of them is guaranteed to be in the result.
    const std::optional<Outid> anchor = CanonicalAnchorOfAllInputs();

    std::vector<UnsignedOutput> payOutputs;
    payOutputs.reserve(vPendingOutputs.size());
    for (const auto& pending : vPendingOutputs) {
        payOutputs.push_back(MaterializeOutput(pending, anchor));
    }
    for (auto& out_ : vOutputs) {
        for (auto& out : out_.second) payOutputs.push_back(out);
    }

    std::vector<Signature> baseOutputSignatures;
    Scalar baseOutputGammas;
    {
        baseOutputGammas = baseOutputGammas - recvOutput.gamma;
        if (recvOutput.out.HasBLSCTKeys()) {
            baseOutputSignatures.push_back(PrivateKey(recvOutput.blindingKey).Sign(recvOutput.out.GetHash()));
        }
        // Any pay-side outputs the caller queued via AddOutput.
        for (auto& out : payOutputs) {
            if (out.out.HasBLSCTRangeProof()) baseOutputGammas = baseOutputGammas - out.gamma;
            if (out.out.HasBLSCTKeys()) baseOutputSignatures.push_back(PrivateKey(out.blindingKey).Sign(out.out.GetHash()));
        }
    }

    nAmounts[TokenId()].nFromFee = 0;
    while (true) {
        CMutableTransaction tx;
        tx.nVersion |= CTransaction::BLSCT_MARKER;
        // Stamp the proof-v2 marker when the outputs are built under the v2
        // transcript (mirrors BuildTx): consensus enforces the flag against
        // the activation height, and CombineHalves ORs it across halves.
        if (m_transcript_v2)
            tx.nVersion |= CTransaction::BLSCT_PROOF_V2_MARKER;

        Scalar gammaAcc = baseOutputGammas;
        std::vector<Signature> txSigs = baseOutputSignatures;
        std::map<TokenId, CAmount> mapInputs;

        // The recv_token output must be present in the half.
        tx.vout.push_back(recvOutput.out);
        for (auto& out : payOutputs)
            tx.vout.push_back(out.out);

        // Add pay-side inputs.
        for (auto& in_ : vInputs) {
            for (auto& in : in_.second) {
                tx.vin.push_back(in.in);
                gammaAcc = gammaAcc + in.gamma;
                txSigs.push_back(in.sk.Sign(in.in.GetHash()));
                mapInputs[in_.first] += in.value.GetUint64();
            }
        }

        // Per-token sufficiency: only tokens we actually pay (have inputs for)
        // must cover their outputs + fee. recv_token is intentionally short and
        // is skipped — the counterparty balances it.
        // Each input token must cover what this half pays out of it plus, for
        // NAV, the fee. The recv_token output is funded by the counterparty and
        // is NOT charged here. pay_amount of pay_token is the gap handed to the
        // counterparty (it becomes their recv); the rest is change.
        std::map<TokenId, CAmount> mapChange;
        for (auto& kv : mapInputs) {
            const TokenId& tid = kv.first;
            const CAmount pay_for_token = (tid == pay_token) ? pay_amount : 0;
            const CAmount fee_for_token = (tid == TokenId()) ? nAmounts[TokenId()].nFromFee : 0;
            if (kv.second < pay_for_token + fee_for_token) return std::nullopt;
            mapChange[tid] = kv.second - pay_for_token - fee_for_token;
        }

        for (auto& change : mapChange) {
            if (change.second == 0) continue;
            auto changeOutput = CreateOutput(changeDestination, change.second, "Change", change.first, Scalar::Rand(), NORMAL, 0, /*fAllowZeroValueRangeProof=*/false, m_transcript_v2);
            gammaAcc = gammaAcc - changeOutput.gamma;
            tx.vout.push_back(changeOutput.out);
            txSigs.push_back(PrivateKey(changeOutput.blindingKey).Sign(changeOutput.out.GetHash()));
        }

        CTxOut fee_out{nAmounts[TokenId()].nFromFee, CScript(OP_RETURN)};
        auto feeKey = blsct::PrivateKey(BlstScalar::Rand());
        fee_out.predicate = blsct::PayFeePredicate(feeKey.GetPublicKey()).GetVch();
        tx.vout.push_back(fee_out);

        txSigs.push_back(PrivateKey(gammaAcc).SignBalance());
        txSigs.push_back(PrivateKey(feeKey).SignFee());
        tx.txSig = Signature::Aggregate(txSigs);

        const CAmount required_fee = GetTransactionWeight(CTransaction(tx)) * nBLSCTDefaultFee + additionalFee;
        if (nAmounts[TokenId()].nFromFee == required_fee) {
            return tx;
        }
        nAmounts[TokenId()].nFromFee = required_fee;
    }
    return std::nullopt;
}

std::optional<BuiltTransaction> TxFactoryBase::CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const CreateTransactionData& transactionData, const std::optional<std::vector<unsigned char>>& blindingSeed, BlindingGenerationFn generationFn)
{
    auto tx = blsct::TxFactoryBase();
    tx.SetTranscriptV2(transactionData.transcript_v2);
    if (blindingSeed) tx.SetBlindingSeed(*blindingSeed);
    if (generationFn) tx.SetBlindingGenerationFn(std::move(generationFn));

    if (transactionData.type == STAKED_COMMITMENT) {
        CAmount inputFromStakedCommitments = 0;
        // Consolidation only folds commitments that share this transaction's
        // delegation identity: plain stakes merge with plain stakes, and a
        // delegated stake only merges with stakes delegated to the same
        // delegate and reward address. Folding across identities would either
        // silently hand undelegated funds to a delegate or silently revoke an
        // existing delegation.
        const std::string delegationId = transactionData.stakeDelegation.has_value() ? transactionData.stakeDelegation->GetId() : "";

        for (const auto& output : inputCandidates) {
            if (output.is_staked_commitment) {
                // With consolidation disabled, leave existing commitments
                // untouched so this stakelock yields a separate commitment.
                // A redelegation additionally folds the commitments of the
                // identities it is moving away from.
                const bool matches = output.delegation == delegationId ||
                                     transactionData.redelegateFromIds.contains(output.delegation);
                if (!transactionData.fConsolidateStakedCommitments || !matches)
                    continue;
                inputFromStakedCommitments += output.amount;
            }

            tx.AddInput(output.amount, output.gamma, output.spendingKey, output.token_id, COutPoint(output.outpoint.hash), output.is_staked_commitment);
        }

        if (transactionData.nAmount + inputFromStakedCommitments < transactionData.minStake) {
            throw std::runtime_error(strprintf("A minimum of %s is required to stake", FormatMoney(transactionData.minStake)));
        }

        bool fSubtractFeeFromAmount = false; // nAmount == inAmount + inputFromStakedCommitments;

        tx.AddOutput(transactionData.destination, transactionData.nAmount + inputFromStakedCommitments, transactionData.sMemo, transactionData.token_id, transactionData.type, transactionData.minStake, fSubtractFeeFromAmount, /*blindingKey=*/std::nullopt, transactionData.nBLSCTDefaultFee, transactionData.stakeDelegation);
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
            tx.AddOutput(transactionData.destination, transactionData.nAmount, transactionData.sMemo, transactionData.token_id, transactionData.type, transactionData.minStake, subtract_fee, /*blindingKey=*/std::nullopt, transactionData.nBLSCTDefaultFee);
        }
    }
    return tx.BuildTx(transactionData.changeDestination, transactionData.minStake, transactionData.type, /*fSubtractedFee=*/false, transactionData.nBLSCTDefaultFee, transactionData.additionalFee);
}

} // namespace blsct
