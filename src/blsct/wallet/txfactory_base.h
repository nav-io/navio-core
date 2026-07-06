// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/txfactory_global.h>
#include <primitives/transaction.h>

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
    CAmount nAmount;
    std::string sMemo;
    TokenId token_id;
    CAmount minStake;
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

    // When true (default), stake operations fold every existing staked
    // commitment of the wallet into the new commitment output, so a wallet
    // holds a single consolidated stake. When false, `stakelock` funds the new
    // stake purely from spendable coins (leaving prior commitments untouched,
    // producing a separate commitment) and `stakeunlock` consumes only the
    // commitments needed to cover the requested amount. Controlled by the
    // `-consolidatestakedcommitments` flag. Disabling it lets a single wallet
    // build the >=2 distinct commitments a PoS membership ring requires.
    bool fConsolidateStakedCommitments{true};

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

struct InputCandidates {
    CAmount amount;
    MclScalar gamma;
    blsct::PrivateKey spendingKey;
    TokenId token_id;
    COutPoint outpoint;
    bool is_staked_commitment;
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

public:
    TxFactoryBase()= default;

    // Normal transfer
    void AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id = TokenId(), const CreateTransactionType& type = NORMAL, const CAmount& minStake = 0, const bool& fSubtractFeeFromAmount = false, const Scalar& blindingKey = Scalar::Rand(), const CAmount& nBLSCTDefaultFee = ::BLSCT_DEFAULT_FEE);
    // Create Token
    void AddOutput(const Scalar& tokenKey, const blsct::TokenInfo& tokenInfo);
    // Mint Token
    void AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const CAmount& mintAmount);
    // Mint NFT
    void AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const uint64_t& nftId, const std::map<std::string, std::string>& nftMetadata);
    bool AddInput(const CAmount& amount, const MclScalar& gamma, const blsct::PrivateKey& spendingKey, const TokenId& token_id, const COutPoint& outpoint, const bool& stakedCommitment = false, const bool& rbf = false);
    //! `additionalFee` lets an aggregation initiator over-fund the fee output so
    //! the combined transaction (own half + K fee-0 candidate halves) meets the
    //! consensus min-fee for the COMBINED weight. Defaults to 0 (normal txs).
    std::optional<CMutableTransaction> BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake = 0, const CreateTransactionType& type = NORMAL, const bool& fSubtractedFee = false, const CAmount& nBLSCTDefaultFee = ::BLSCT_DEFAULT_FEE, const CAmount& additionalFee = 0);
    static std::optional<CMutableTransaction> CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const CreateTransactionData& transactionData);

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
};

} // namespace blsct
