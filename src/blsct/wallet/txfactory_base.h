// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/delegation.h>
#include <blsct/wallet/txfactory_global.h>
#include <primitives/transaction.h>

#include <optional>

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
        Scalar blindingKey;
    };
    std::optional<SubtractFeeOutput> subtractFeeOutput;

public:
    TxFactoryBase()= default;

    // Normal transfer
    void AddOutput(const SubAddress& destination, const CAmount& nAmount, std::string sMemo, const TokenId& token_id = TokenId(), const CreateTransactionType& type = NORMAL, const CAmount& minStake = 0, const bool& fSubtractFeeFromAmount = false, const Scalar& blindingKey = Scalar::Rand(), const CAmount& nBLSCTDefaultFee = ::BLSCT_DEFAULT_FEE, const std::optional<delegation::DelegationRequest>& stakeDelegation = std::nullopt);
    // Create Token
    void AddOutput(const Scalar& tokenKey, const blsct::TokenInfo& tokenInfo);
    // Mint Token
    void AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const CAmount& mintAmount);
    // Mint NFT
    void AddOutput(const Scalar& tokenKey, const SubAddress& destination, const blsct::PublicKey& tokenPublicKey, const uint64_t& nftId, const std::map<std::string, std::string>& nftMetadata);
    bool AddInput(const CAmount& amount, const MclScalar& gamma, const blsct::PrivateKey& spendingKey, const TokenId& token_id, const COutPoint& outpoint, const bool& stakedCommitment = false, const bool& rbf = false);
    std::optional<CMutableTransaction> BuildTx(const blsct::DoublePublicKey& changeDestination, const CAmount& minStake = 0, const CreateTransactionType& type = NORMAL, const bool& fSubtractedFee = false, const CAmount& nBLSCTDefaultFee = ::BLSCT_DEFAULT_FEE);
    static std::optional<CMutableTransaction> CreateTransaction(const std::vector<InputCandidates>& inputCandidates, const CreateTransactionData& transactionData);
};

} // namespace blsct
