// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_WALLET_TXFACTORY_BASE_H
#define NAVIO_BLSCT_WALLET_TXFACTORY_BASE_H

#include <blsct/arith/blst/blst.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/blinding_key.h>
#include <blsct/wallet/delegation.h>
#include <blsct/wallet/txfactory_global.h>
#include <primitives/transaction.h>

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace blsct {
// Maximum number of inputs the factory will put in a single transaction. Each
// input adds weight, so an unbounded count (e.g. spending thousands of small PoS
// staking outputs at once) would exceed MAX_STANDARD_TX_WEIGHT and be rejected
// at broadcast. Beyond this, callers must split the spend across transactions
// (see the 'consolidate' RPC). Chosen well under the weight limit to leave room
// for outputs and range proofs.
static constexpr size_t MAX_TX_INPUT_COUNT = 1000;

// Default for the `-consolidatestakedcommitments` flag. When true, stake
// operations fold a wallet's existing staked commitments into the new
// commitment so the wallet holds a single consolidated stake. Set false to keep
// each stakelock as its own commitment.
static constexpr bool DEFAULT_CONSOLIDATE_STAKED_COMMITMENTS{true};

struct CreateTransactionData {
    CreateTransactionType type;
    blsct::TokenInfo tokenInfo;
    blsct::DoublePublicKey changeDestination;
    SubAddress destination;
    // Zero-initialized: the create-token and NFT-mint constructors never set
    // these, yet coin selection reads nAmount as its input-value limit.
    CAmount nAmount{0};
    std::string sMemo;
    TokenId token_id;
    CAmount minStake{0};
    // Per-byte BLSCT fee rate the wallet will price the transaction at.
    // Defaults to `BLSCT_DEFAULT_FEE`; production callers (RPC / wallet
    // helpers) overwrite this with `Params().GetConsensus().nBLSCTDefaultFee`
    // so wallet-built transactions match the consensus minimum-fee rule
    // enforced by `blsct::VerifyTx`.
    CAmount nBLSCTDefaultFee{::BLSCT_DEFAULT_FEE};
    // Extra fee added on top of this tx's own required fee, used by an
    // aggregation initiator to cover the weight of the fee-0 cover candidates
    // it will combine with. 0 for ordinary sends.
    CAmount additionalFee{0};
    // Proof transcript version to build outputs under (rule A: set true when
    // chain tip + 1 >= Consensus::nBLSCTProofV2Height). Production callers set
    // it from the chain tip; defaults to the legacy transcript.
    bool transcript_v2{false};

    // When true, the recipient bears the transaction fee: the output value is
    // reduced by the total fee instead of the fee being added on top and taken
    // from change. Only honored for NORMAL native-token sends. This is the
    // BLSCT equivalent of the wallet's `subtractfeefromamount`.
    bool fSubtractFeeFromAmount{false};

    // When true (default), stake operations fold every existing staked
    // commitment of the wallet into the new commitment output, so a wallet
    // holds a single consolidated stake. When false, `stakelock` funds the new
    // stake purely from spendable coins (leaving prior commitments untouched,
    // producing a separate commitment) and `stakeunlock` consumes only the
    // commitments needed to cover the requested amount. Controlled by the
    // `-consolidatestakedcommitments` flag. Disabling it lets a single wallet
    // build the >=2 distinct commitments a PoS membership ring requires.
    bool fConsolidateStakedCommitments{true};

    // When set (delegatestake), the staked output carries an encrypted
    // delegation payload addressed to this delegate so a third-party staker
    // can stake it without any wallet keys. Only meaningful for
    // STAKED_COMMITMENT transactions.
    std::optional<delegation::DelegationRequest> stakeDelegation{std::nullopt};

    // When non-empty (redelegatestake), staked commitments whose delegation
    // identity is in this set are folded into the new staked output in
    // addition to those matching stakeDelegation's identity — this is what
    // moves a delegation to a new delegate or reward address in a single
    // transaction, without ever leaving the staking set.
    std::set<std::string> redelegateFromIds{};

    Scalar tokenKey;
    std::map<std::string, std::string> nftMetadata;

    CreateTransactionData(const blsct::DoublePublicKey& changeDestination,
                          const SubAddress& destination,
                          const CAmount& nAmount,
                          const std::string& sMemo,
                          const TokenId& token_id,
                          const CreateTransactionType& type,
                          const CAmount& minStake) : type(type),
                                                     changeDestination(changeDestination),
                                                     destination(destination),
                                                     nAmount(nAmount),
                                                     sMemo(sMemo),
                                                     token_id(token_id),
                                                     minStake(minStake)
    {
    }

    CreateTransactionData(const SubAddress& destination,
                          const CAmount& nAmount,
                          const std::string& sMemo,
                          const TokenId& token_id,
                          const CreateTransactionType& type,
                          const CAmount& minStake) : type(type),
                                                     destination(destination),
                                                     nAmount(nAmount),
                                                     sMemo(sMemo),
                                                     token_id(token_id),
                                                     minStake(minStake) {}


    CreateTransactionData(const SubAddress& destination,
                          const CAmount& nAmount,
                          const std::string& sMemo) : type(NORMAL),
                                                      destination(destination),
                                                      nAmount(nAmount),
                                                      sMemo(sMemo) {}

    CreateTransactionData(const blsct::TokenInfo& tokenInfo) : type(TX_CREATE_TOKEN), tokenInfo(tokenInfo) {}

    CreateTransactionData(const blsct::TokenInfo& tokenInfo, const CAmount& mintAmount, const SubAddress& destination) : type(TX_MINT_TOKEN), tokenInfo(tokenInfo), destination(destination), nAmount(mintAmount), token_id(TokenId(tokenInfo.publicKey.GetHash())) {}

    CreateTransactionData(const blsct::TokenInfo& tokenInfo, const uint64_t& nftId, const SubAddress& destination, const std::map<std::string, std::string>& nftMetadata) : type(TX_MINT_TOKEN), tokenInfo(tokenInfo), destination(destination), token_id(TokenId(tokenInfo.publicKey.GetHash(), nftId)), nftMetadata(nftMetadata) {}
};

// A transaction built by the factory together with the hash of the output that
// pays the destination it was built for. BuildTx randomises output order before
// returning, so the recipient cannot be recovered positionally by the caller;
// it is recorded here while the build order is still known.
//! Claims the next build generation for an anchor, persisting the bump.
//! nullopt = could not reserve, in which case the factory falls back to a
//! random scalar rather than reusing a derived one. See
//! blsct::KeyMan::ReserveBlindingGeneration.
using BlindingGenerationFn = std::function<std::optional<uint32_t>(const Outid& anchor)>;

struct BuiltTransaction {
    CMutableTransaction tx;
    uint256 recipientOutputHash;
    // Blinding scalars of the outputs this factory built, keyed by output
    // hash. TEST-ONLY: no production caller reads this. The wallet
    // deliberately does not persist the scalars -- they are the authority that
    // signs for an output, and the wallet database stores records in the clear
    // -- so `signblsctoutput` always re-derives through
    // blsct::DeriveBlindingKey. What this field is for is letting a test
    // assert that what was BUILT matches what the derivation RECOVERS, which
    // is the property the whole scheme rests on. These are secrets: do not
    // log them and do not write them anywhere.
    std::map<uint256, Scalar> blindingKeys;
};

struct InputCandidates {
    CAmount amount;
    BlstScalar gamma;
    blsct::PrivateKey spendingKey;
    TokenId token_id;
    COutPoint outpoint;
    bool is_staked_commitment;
    // Delegation identity (DelegationRequest::GetId()) of a delegated staked
    // commitment; empty for undelegated outputs. Stake consolidation only
    // folds commitments that share the same identity.
    std::string delegation{};
};

class TxFactoryBase
{
protected:
    CMutableTransaction tx;
    std::map<TokenId, std::vector<UnsignedOutput>>
        vOutputs;
    std::map<TokenId, std::vector<UnsignedInput>>
        vInputs;
    std::map<TokenId, Amounts>
        nAmounts;

    // An ordinary transfer output queued by AddOutput, not yet materialized.
    //
    // Materialization is deferred to BuildTx because a recoverable blinding
    // scalar is derived from an INPUT outpoint (see blinding_key.h), and which
    // inputs a transaction ends up spending is only settled by BuildTx's coin
    // selection. Before this, AddOutput built the CTxOut immediately, which
    // fixed the blinding key -- and therefore the whole output, since the key
    // seeds the ephemeral key, the shared nonce and the range proof -- before
    // any input was known.
    struct PendingOutput {
        SubAddress destination;
        CAmount amount;
        std::string memo;
        TokenId token_id;
        CreateTransactionType type;
        CAmount minStake;
        // The caller's explicitly pinned blinding scalar (the Scalar::Rand()
        // opt-out). std::nullopt means "derive it".
        std::optional<Scalar> blindingKey;
        std::optional<delegation::DelegationRequest> stakeDelegation;
        // The ordinal this output was queued with: the `counter` the
        // derivation is keyed on. Assigned once at AddOutput time so it stays
        // stable across BuildTx's fee-fixpoint passes, and deliberately
        // unrelated to where the output finally lands in vout (BuildTx
        // shuffles, and block aggregation renumbers).
        uint32_t ordinal;
    };
    std::vector<PendingOutput> vPendingOutputs;

    // A pending subtract-fee-from-amount recipient. Its final value is
    // (amount - total transaction fee), and the total fee is only known once
    // BuildTx's fee fixpoint converges. Because BLSCT input/output serialized
    // sizes are value-independent, the fee is identical whatever value we
    // ultimately commit, so BuildTx can (re)build this output at the reduced
    // value inside the fixpoint without perturbing the fee. AddOutput records
    // it here rather than materializing it in vOutputs immediately.
    struct SubtractFeeOutput {
        SubAddress destination;
        CAmount amount;
        std::string memo;
        TokenId token_id;
        CreateTransactionType type;
        CAmount minStake;
        std::optional<Scalar> blindingKey;
        uint32_t ordinal;
    };
    std::optional<SubtractFeeOutput> subtractFeeOutput;

    // Proof transcript version the outputs built by this factory should use.
    // Set from the activation height of the block this tx targets (rule A:
    // chain tip + 1 >= nBLSCTProofV2Height). Defaults to the legacy transcript
    // so callers that do not set it are unaffected while the gate is dormant.
    bool m_transcript_v2 = false;

    // 32-byte HD-seed material the output blinding scalars are derived from.
    // Unset for factories with no wallet behind them (raw/offline builders and
    // most unit tests), in which case blinding keys fall back to
    // Scalar::Rand() and the resulting outputs are simply not recoverable --
    // exactly the behaviour every output had before this change.
    std::optional<std::vector<unsigned char>> m_blinding_seed;
    BlindingGenerationFn m_blinding_generation_fn;
    //! Generation claimed for each anchor during THIS build.
    //!
    //! The fee fixpoint materializes the same outputs repeatedly (up to
    //! MAX_FEE_FIXPOINT_PASSES times) and coin selection may revisit an anchor
    //! across passes. Claiming per call would burn a generation per pass and,
    //! worse, make the built outputs disagree about which generation they used.
    //! One claim per anchor per factory: the outputs that survive the fixpoint
    //! are the ones the generation was claimed for.
    mutable std::map<Outid, uint32_t> m_claimed_generations;

    // Next sender-assigned output ordinal. Change outputs continue the
    // sequence after everything AddOutput queued.
    uint32_t m_next_output_ordinal{0};

    //! The blinding scalar to build an output with: the caller's pinned key
    //! when there is one, else the seed derivation, else a random scalar.
    Scalar BlindingKeyFor(const std::optional<Scalar>& pinned, uint32_t ordinal, const std::optional<Outid>& anchor) const;

    //! The canonical anchor over a selected input set: the lexicographically
    //! smallest outid among them (blsct::CanonicalAnchor).
    //!
    //! Canonical rather than positional because no position survives to
    //! recovery time -- BuildTx shuffles vin, and block aggregation splices in
    //! other senders' inputs. It must still be an input that SURVIVES into the
    //! built transaction, which is why it is computed from the set coin
    //! selection actually chose rather than from everything the factory holds:
    //! deriving from an input that selection then drops would leave the output
    //! unrecoverable.
    static std::optional<Outid> CanonicalAnchorOf(const std::vector<const UnsignedInput*>& selected);

    //! The canonical anchor over every input the factory holds, for builders
    //! (BuildUnbalancedHalf) that spend all of them unconditionally.
    std::optional<Outid> CanonicalAnchorOfAllInputs() const;

    //! Build a queued output, assigning its blinding scalar from `anchor`.
    UnsignedOutput MaterializeOutput(const PendingOutput& pending, const std::optional<Outid>& anchor) const;

public:
    TxFactoryBase()= default;

    void SetTranscriptV2(bool transcript_v2) { m_transcript_v2 = transcript_v2; }

    //! Enable recoverable blinding keys for every output this factory builds
    //! (including change). `seed` must be 32 bytes; see blinding_key.h.
    void SetBlindingSeed(const std::vector<unsigned char>& seed) { m_blinding_seed = seed; }

    void SetBlindingGenerationFn(BlindingGenerationFn fn) { m_blinding_generation_fn = std::move(fn); }

    // Normal transfer.
    //
    // `blindingKey` defaults to std::nullopt, meaning "derive a recoverable
    // scalar from the factory's blinding seed". Passing Scalar::Rand()
    // explicitly is the opt-out for callers that genuinely want an
    // unrecoverable random key.
    void AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id = TokenId(), const CreateTransactionType& type = NORMAL, const CAmount& minStake = 0, const bool& fSubtractFeeFromAmount = false, const std::optional<Scalar>& blindingKey = std::nullopt, const CAmount& nBLSCTDefaultFee = ::BLSCT_DEFAULT_FEE, const std::optional<delegation::DelegationRequest>& stakeDelegation = std::nullopt);
    // Create Token
    void AddOutput(const Scalar& tokenKey, const blsct::TokenInfo& tokenInfo);
    // Mint Token
    void AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const CAmount& mintAmount);
    // Mint NFT
    void AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const uint64_t& nftId, const std::map<std::string, std::string>& nftMetadata);
    bool AddInput(const CAmount& amount, const BlstScalar& gamma, const blsct::PrivateKey& spendingKey, const TokenId& token_id, const COutPoint& outpoint, const bool& stakedCommitment = false, const bool& rbf = false);
    //! Number of inputs added so far, across all tokens.
    size_t InputCount() const;
    //! `additionalFee` lets an aggregation initiator over-fund the fee output so
    //! the combined transaction (own half + K fee-0 candidate halves) meets the
    //! consensus min-fee for the COMBINED weight. Defaults to 0 (normal txs).
    //!
    //! `emitFeeOutput=false` builds a fee-0 aggregation *candidate* half: it
    //! carries no fee output and no fee signature (only its balance + input
    //! signatures), so CombineHalves can merge many candidates behind the
    //! initiator's single fee output. The caller must pass a value-balanced set
    //! of inputs/outputs (a self-spend), since no fee is charged.
    std::optional<BuiltTransaction> BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake = 0, const CreateTransactionType& type = NORMAL, const bool& fSubtractedFee = false, const CAmount& nBLSCTDefaultFee = ::BLSCT_DEFAULT_FEE, const CAmount& additionalFee = 0, const bool& emitFeeOutput = true);
    //! `blindingSeed`, when supplied, makes every output of the built
    //! transaction carry a blinding scalar recoverable from that seed. Pass
    //! blsct::KeyMan::GetBlindingSeed(); std::nullopt keeps the old random
    //! (unrecoverable) keys.
    //!
    //! `generationFn` must accompany a seed for the outputs to actually be
    //! derived: without it the factory falls back to random keys rather than
    //! risk deriving the same scalar twice over one input set. Pass
    //! blsct::KeyMan::ReserveBlindingGeneration().
    static std::optional<BuiltTransaction> CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const CreateTransactionData& transactionData, const std::optional<std::vector<unsigned char>>& blindingSeed = std::nullopt, BlindingGenerationFn generationFn = {});

    //! Build a deliberately UNBALANCED half-transaction for an atomic swap.
    //!
    //! Unlike BuildTx, a swap half may output a token it does not input: the
    //! taker pays `pay_token` (covered by its own inputs) and receives
    //! `recv_amount` of `recv_token` from the counterparty. The `recv_token`
    //! output has no matching input here — the maker's half supplies it, so the
    //! combined transaction balances per TokenId. This builder therefore:
    //!   - emits the recv_token output (its gamma IS folded into the balance
    //!     signature, so the half's own sig stays valid after Signature::Aggregate),
    //!   - does NOT require recv_token inputs (skips the per-token sufficiency
    //!     check for it),
    //!   - funds the fee from the pay_token (NAV) side and over-funds by
    //!     `additionalFee` so the COMBINED tx clears the consensus minimum.
    //!
    //! Inputs must already be added via AddInput (pay_token coins covering
    //! pay_amount + fee). `changeDestination` receives pay_token change.
    //! Returns std::nullopt if the pay_token inputs are insufficient.
    //! `pay_token`/`pay_amount`: the asset+amount this half hands to the
    //! counterparty (the gap left after change; becomes their recv).
    //! `recv_token`/`recv_amount`: the asset+amount this half receives (output
    //! with no matching input; supplied by the counterparty's half).
    //! Inputs (added via AddInput) must be `pay_token` covering
    //! `pay_amount` + fee. Fee is always NAV; if `pay_token` is not NAV the
    //! caller must also AddInput enough NAV to cover the fee.
    std::optional<CMutableTransaction> BuildUnbalancedHalf(
        const blsct::DoublePublicKey& changeDestination,
        const SubAddress& recvDestination,
        const TokenId& pay_token,
        const CAmount& pay_amount,
        const TokenId& recv_token,
        const CAmount& recv_amount,
        const CAmount& nBLSCTDefaultFee,
        const CAmount& additionalFee = 0);

    //! Feed spare NAV coins into this factory one at a time and rebuild until
    //! the unbalanced half builds or the spares run out. BuildUnbalancedHalf
    //! returns nullopt exactly when some input token cannot cover its outgo
    //! plus (for NAV) the fee, and the required fee is a moving target — it
    //! depends on the final transaction weight — so no up-front gathering
    //! limit can guarantee coverage. Adding one more coin and rebuilding
    //! converges instead, and also lets the fee be paid from several small NAV
    //! coins rather than one.
    //! Throws std::runtime_error if the half would need more than
    //! MAX_TX_INPUT_COUNT inputs.
    std::optional<CMutableTransaction> BuildHalfAddingSpares(
        const std::vector<InputCandidates>& spares,
        size_t first_spare,
        const std::function<std::optional<CMutableTransaction>()>& build);
};

} // namespace blsct

#endif // NAVIO_BLSCT_WALLET_TXFACTORY_BASE_H
