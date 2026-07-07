// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_WALLET_BRIDGE_TXFACTORY_H
#define NAVIO_BLSCT_WALLET_BRIDGE_TXFACTORY_H

#include <blsct/bridge/predicates.h>
#include <blsct/wallet/keyman.h>
#include <blsct/wallet/txfactory.h>

#include <optional>
#include <string>
#include <vector>

// Wallet-side builders for the five NBP bridge transaction types
// (navio-bridge-protocol DESIGN.md §4/§7/§8/§9). Every builder returns a
// fully-signed BLSCT CMutableTransaction ready for broadcast, mirroring
// TxFactoryBase::BuildTx (fee fixpoint, PayFee output, SignBalance/SignFee
// aggregation) but extended with the bridge-specific balance terms:
// transparent predicate outputs and consensus-minted pseudo-inputs /
// consensus-burned pseudo-outputs, matching blsct::VerifyTx's handling of
// NBP predicates (blsct/wallet/verification.cpp).

namespace blsct {
namespace bridge {

//! Deterministic guardian key: GetTokenKey(SHA256("nbp/guardian/v1")).
//! Every bridge RPC uses this same derivation.
blsct::PrivateKey GetGuardianKey(blsct::KeyMan* blsct_km);

//! DST-prefixed message builders. These MUST match the consensus verifier
//! (blsct/bridge/logic.cpp) byte for byte.
std::vector<unsigned char> DstMessage(const std::string& dst, const std::vector<unsigned char>& payload);
std::vector<unsigned char> PopMessage(const std::vector<unsigned char>& pk);
std::vector<unsigned char> ExitMessage(const std::vector<unsigned char>& pk);
//! DST_POP ‖ "withdraw" ‖ pk ‖ SHA256(scriptPubKey) ‖ nValue (8 bytes LE).
//! The signature cannot cover the carrying output's own hash (the predicate
//! holding it is part of that hash), so it binds script and amount directly
//! — same as nbp::ExecGuardianWithdraw.
std::vector<unsigned char> WithdrawMessage(const std::vector<unsigned char>& pk, const CTxOut& out);
std::vector<unsigned char> ChallengeMessage(const uint256& depositId);

//! claim_commit = SHA256(dpk.GetVch()(96B) ‖ r(32B)) — matches consensus.
uint256 ComputeClaimCommit(const blsct::DoublePublicKey& dpk, const uint256& r);

//! The wallet's canonical claim destination: sub-address {0, 0}. Both
//! nbpgetclaimcommit and nbpclaimdeposit use this so the dpk opened in the
//! mint predicate is the one committed before the Ethereum deposit.
blsct::DoublePublicKey GetClaimDestination(blsct::KeyMan* blsct_km);

// --- transaction builders ---------------------------------------------------
// All builders take the wallet lock internally, do coin selection for the
// funding they need and throw std::runtime_error / return std::nullopt on
// failure (nullopt = insufficient funds).

//! a. Guardian register: OP_RETURN output, transparent nValue = bond,
//! NBP_GUARDIAN_REGISTER predicate (PoP + mock SPP). Funded from wallet NAV.
std::optional<CMutableTransaction> BuildGuardianRegisterTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const CAmount& bond, uint32_t sppRefHeight);

//! b. Guardian exit: OP_RETURN nValue=0 output with NBP_GUARDIAN_EXIT. Fee only.
std::optional<CMutableTransaction> BuildGuardianExitTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km);

//! c. Guardian withdraw: spendable transparent output nValue = bond to the
//! wallet, NBP_GUARDIAN_WITHDRAW predicate. Consensus mints the bond
//! (pseudo-input); inputs pay the fee only.
std::optional<CMutableTransaction> BuildGuardianWithdrawTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km, const CAmount& bond);

//! d. Bridge mint (claim): confidential output paying `amount` of the
//! wrapped token to the wallet's claim destination, carrying the
//! NBP_BRIDGE_MINT predicate; consensus pseudo-input supplies the token
//! value. Inputs pay the fee only.
std::optional<CMutableTransaction> BuildBridgeMintTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
    uint64_t ethChainId, const std::vector<unsigned char>& token,
    const uint256& depositId, const CAmount& amount, const uint256& r,
    const std::vector<unsigned char>& bitfield, const blsct::Signature& aggSig);

//! e. Bridge burn: spends wallet wrapped-token coins (>= amount, hidden
//! change if over); OP_RETURN nValue=0 output with NBP_BRIDGE_BURN; the
//! consensus pseudo-output destroys `amount` of the token. NAV pays the fee.
std::optional<CMutableTransaction> BuildBridgeBurnTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
    uint64_t ethChainId, const std::vector<unsigned char>& token,
    const CAmount& amount, const std::vector<unsigned char>& ethRecipient);

//! f. Challenge: OP_RETURN output with transparent nValue = challengeBond and
//! NBP_BRIDGE_CHALLENGE predicate, funded from wallet NAV.
std::optional<CMutableTransaction> BuildChallengeTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
    const uint256& depositId, const CAmount& challengeBond);

//! g. Resolve: verdict=1 → spendable output nValue = refundAmount
//! (consensus-minted); verdict=0 → OP_RETURN nValue=0. Fee-only inputs.
std::optional<CMutableTransaction> BuildResolveTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
    const uint256& depositId, const uint256& challengeTxid, uint8_t verdict,
    const std::vector<unsigned char>& bitfield, const blsct::Signature& aggSig,
    const CAmount& refundAmount);

//! h. Guardian slash: spendable output nValue = rewardAmount (consensus-
//! minted reporter reward) with NBP_GUARDIAN_SLASH evidence. Fee-only inputs.
std::optional<CMutableTransaction> BuildSlashTx(
    wallet::CWallet* wallet, blsct::KeyMan* blsct_km,
    uint8_t evidenceType, const blsct::PublicKey& guardianKey,
    const std::vector<unsigned char>& msg1, const blsct::Signature& sig1,
    const std::vector<unsigned char>& msg2, const blsct::Signature& sig2,
    const CAmount& rewardAmount);

} // namespace bridge
} // namespace blsct

#endif // NAVIO_BLSCT_WALLET_BRIDGE_TXFACTORY_H
