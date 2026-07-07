// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BRIDGE_PREDICATES_H
#define NAVIO_BLSCT_BRIDGE_PREDICATES_H

#include <blsct/double_public_key.h>
#include <blsct/public_key.h>
#include <blsct/signature.h>
#include <consensus/amount.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

// NBP bridge predicate payloads (navio-bridge-protocol DESIGN.md §4/§7/§8/§9,
// IMPLEMENTATION.md WP1/WP7-WP10). The enum values live in
// blsct/tokens/predicate_parser.h next to the existing operations; these
// structs only define the payloads and their serialization.
//
// Prototype conventions:
//  - Cross-chain commitments (claim_commit) use SHA256 (navio-core has no
//    keccak; Ethereum has a SHA256 precompile). deposit_id is treated as an
//    opaque 32-byte identifier minted by the vault.
//  - BLS domain separation is done by prefixing the DST string to the signed
//    message (nbp::DST_*), using the existing blsct signing API.

namespace nbp {

//! Guardian registration (DESIGN §4.1). The carrying output must be a
//! transparent bond of value >= MIN_BOND.
struct GuardianRegisterPredicate {
    blsct::PublicKey guardianKey;
    //! PoP = Sign(sk_g, DST_POP ‖ pk_g)
    blsct::Signature proofOfPossession;
    //! Stake-participation proof. On blsctregtest the mock encoding
    //! {0x01} is accepted (IMPLEMENTATION.md P1); real SPP verification is
    //! not implemented in the prototype.
    std::vector<unsigned char> sppBlob;
    //! Height of the staked-set snapshot the SPP refers to.
    uint32_t sppRefHeight{0};

    SERIALIZE_METHODS(GuardianRegisterPredicate, obj)
    {
        READWRITE(obj.guardianKey, obj.proofOfPossession, obj.sppBlob, obj.sppRefHeight);
    }
};

//! Voluntary exit; bond becomes spendable after nUnbondingBlocks.
struct GuardianExitPredicate {
    blsct::PublicKey guardianKey;
    //! Sign(sk_g, DST_POP ‖ "exit" ‖ pk_g) — replay is harmless (idempotent).
    blsct::Signature exitSig;

    SERIALIZE_METHODS(GuardianExitPredicate, obj)
    {
        READWRITE(obj.guardianKey, obj.exitSig);
    }
};

//! Objective slashing evidence (DESIGN §9): S1 checkpoint equivocation,
//! S2 wrong-roots checkpoint, S5 resolution-vote equivocation.
struct GuardianSlashPredicate {
    uint8_t evidenceType{0}; // 1 = S1, 2 = S2, 5 = S5
    blsct::PublicKey guardianKey;
    std::vector<unsigned char> msg1;
    blsct::Signature sig1;
    std::vector<unsigned char> msg2; // unused for S2
    blsct::Signature sig2;           // unused for S2

    SERIALIZE_METHODS(GuardianSlashPredicate, obj)
    {
        READWRITE(obj.evidenceType, obj.guardianKey, obj.msg1, obj.sig1, obj.msg2, obj.sig2);
    }
};

//! Peg-in mint (DESIGN §7.3). Outputs of the carrying tx are confidential
//! BLSCT outputs of the wrapped token; consensus forces them to sum to
//! `amount` via the transparent pseudo-input balance rule.
struct BridgeMintPredicate {
    uint64_t ethChainId{0};
    std::vector<unsigned char> token;   // 20-byte ERC20 address
    uint256 depositId;                  // opaque id minted by the vault
    CAmount amount{0};
    uint256 claimCommit;                // SHA256(dpk_ser ‖ r)
    blsct::DoublePublicKey dpk;         // opening of claimCommit
    uint256 r;
    std::vector<unsigned char> bitfield; // attester set over current committee
    blsct::Signature aggSig;             // aggregate over DST_ATT ‖ att_bytes

    SERIALIZE_METHODS(BridgeMintPredicate, obj)
    {
        READWRITE(obj.ethChainId, obj.token, obj.depositId, obj.amount,
                  obj.claimCommit, obj.dpk, obj.r, obj.bitfield, obj.aggSig);
    }
};

//! Peg-out burn (DESIGN §8). Spends wrapped-token inputs; consensus forces
//! hidden inputs to sum to `amount` (mirror balance rule) and appends a
//! PegOutEvent to the epoch.
struct BridgeBurnPredicate {
    uint64_t ethChainId{0};
    std::vector<unsigned char> token;        // 20-byte ERC20 address
    CAmount amount{0};
    std::vector<unsigned char> ethRecipient; // 20 bytes

    SERIALIZE_METHODS(BridgeBurnPredicate, obj)
    {
        READWRITE(obj.ethChainId, obj.token, obj.amount, obj.ethRecipient);
    }
};

//! Freeze an immature mint (DESIGN §7.4). The carrying output must be a
//! transparent challenge bond of value == challengeBond.
struct BridgeChallengePredicate {
    uint256 depositId;
    blsct::PublicKey guardianKey; // must be a registered guardian
    //! Sign(sk_g, DST_RES ‖ "challenge" ‖ depositId)
    blsct::Signature challengeSig;

    SERIALIZE_METHODS(BridgeChallengePredicate, obj)
    {
        READWRITE(obj.depositId, obj.guardianKey, obj.challengeSig);
    }
};

//! Committee verdict on a challenge (DESIGN §7.4): 2/3-weight aggregate
//! over DST_RES ‖ res_bytes.
struct BridgeResolvePredicate {
    uint256 challengeTxid;
    uint256 depositId;
    uint8_t verdict{0}; // 1 = uphold (revoke mint), 0 = reject
    std::vector<unsigned char> bitfield;
    blsct::Signature aggSig;

    SERIALIZE_METHODS(BridgeResolvePredicate, obj)
    {
        READWRITE(obj.challengeTxid, obj.depositId, obj.verdict, obj.bitfield, obj.aggSig);
    }
};

} // namespace nbp

#endif // NAVIO_BLSCT_BRIDGE_PREDICATES_H
