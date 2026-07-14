// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_WALLET_DELEGATION_H
#define NAVIO_BLSCT_WALLET_DELEGATION_H

#include <blsct/arith/mcl/mcl.h>
#include <consensus/amount.h>

#include <optional>
#include <string>
#include <vector>

namespace blsct {
namespace delegation {

//! Plaintext carried inside a stake-delegation blob for the delegate: the
//! opening of the staked Pedersen commitment plus the address the delegate
//! must pay block rewards to. Knowing (value, gamma) is enough to build a
//! proof of stake but not to spend or unstake the output, which keeps the
//! principal safe.
struct DelegationInfo {
    CAmount value{0};
    MclScalar gamma;
    std::string rewardAddress;
};

//! What a wallet needs to know to delegate a new staked output: whom to
//! delegate to and where that delegate must send block rewards. Also what
//! the owner wallet recovers back from its own delegated outputs (via the
//! owner section of the blob), so delegations survive a wallet restore and
//! outputs sharing the same delegation can be identified and consolidated.
struct DelegationRequest {
    MclG1Point delegateKey;
    std::string rewardAddress;

    //! Stable identity of a delegation: same delegate and same reward
    //! address. Used to group staked outputs for consolidation.
    std::string GetId() const;
};

//! Size of a compressed G1 point (ephemeral and delegate public keys).
constexpr size_t DELEGATION_POINT_SIZE = 48;

//! Returns true if the vector looks like a stake-delegation payload
//! (magic + version prefix). Cheap filter before attempting decryption.
bool IsDelegationData(const std::vector<unsigned char>& data);

//! Encrypt `info` to the delegate identified by `request.delegateKey`.
//! Produces: magic || version || E || owner-section || delegate-section,
//! where E is a fresh ephemeral key, the delegate section is AEAD-encrypted
//! under ECDH(e, delegateKey), and the owner section carries
//! (delegateKey, rewardAddress) AEAD-encrypted under a key derived from the
//! output's BLSCT nonce — the same secret the owner already uses to recover
//! the output's amount — so the owner wallet can re-derive the delegation
//! from the chain alone.
std::vector<unsigned char> Encrypt(const DelegationInfo& info, const DelegationRequest& request, const MclG1Point& nonce);

//! Delegate side: attempt to decrypt the delegate section with the delegate's
//! private key. Returns std::nullopt on any mismatch (wrong recipient,
//! tampered data, unknown version).
std::optional<DelegationInfo> TryDecrypt(const std::vector<unsigned char>& data, const MclScalar& delegatePrivKey);

//! Owner side: recover (delegateKey, rewardAddress) from the owner section
//! using the output's BLSCT nonce. Returns std::nullopt if the payload is
//! not a delegation or the nonce does not match.
std::optional<DelegationRequest> RecoverOwnerInfo(const std::vector<unsigned char>& data, const MclG1Point& nonce);

} // namespace delegation
} // namespace blsct

#endif // NAVIO_BLSCT_WALLET_DELEGATION_H
