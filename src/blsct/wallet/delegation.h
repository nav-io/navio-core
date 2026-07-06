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

//! Plaintext carried inside a stake-delegation blob: the opening of the
//! staked Pedersen commitment plus the address the delegate must pay block
//! rewards to. Knowing (value, gamma) is enough to build a proof of stake
//! but not to spend or unstake the output, which keeps the principal safe.
struct DelegationInfo {
    CAmount value{0};
    MclScalar gamma;
    std::string rewardAddress;
};

//! What a wallet needs to know to delegate a new staked output: whom to
//! delegate to and where that delegate must send block rewards.
struct DelegationRequest {
    MclG1Point delegateKey;
    std::string rewardAddress;
};

//! Size of a compressed G1 point (the ephemeral public key prefix).
constexpr size_t EPHEMERAL_KEY_SIZE = 48;

//! Returns true if the vector looks like a stake-delegation payload
//! (magic + version prefix). Cheap filter before attempting decryption.
bool IsDelegationData(const std::vector<unsigned char>& data);

//! Encrypt `info` to the delegate identified by `delegateKey` (a G1 public
//! key). Produces: magic || version || E || AEAD(plaintext), where E is a
//! fresh ephemeral key and the AEAD key is derived from ECDH(e, delegateKey).
std::vector<unsigned char> Encrypt(const DelegationInfo& info, const MclG1Point& delegateKey);

//! Attempt to decrypt a delegation payload with the delegate's private key.
//! Returns std::nullopt on any mismatch (wrong recipient, tampered data,
//! unknown version). Constant-shaped: the only early-outs are on public
//! structure (magic/length), not on key material.
std::optional<DelegationInfo> TryDecrypt(const std::vector<unsigned char>& data, const MclScalar& delegatePrivKey);

} // namespace delegation
} // namespace blsct

#endif // NAVIO_BLSCT_WALLET_DELEGATION_H
