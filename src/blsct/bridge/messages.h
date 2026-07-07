// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BRIDGE_MESSAGES_H
#define NAVIO_BLSCT_BRIDGE_MESSAGES_H

#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace nbp {

//! BLS signing domains (navio-bridge-protocol IMPLEMENTATION.md §3.1).
//! Distinct from every existing navio-core signing domain so bridge
//! signatures are non-transplantable across contexts.
inline const std::string DST_POP{"NAVIO-NBP-V1-POP"};
inline const std::string DST_CKPT{"NAVIO-NBP-V1-CKPT"};
inline const std::string DST_ATT{"NAVIO-NBP-V1-ATT"};
inline const std::string DST_RES{"NAVIO-NBP-V1-RES"};

//! Cross-chain byte layouts (IMPLEMENTATION.md §3.2/§3.3/§3.5). All
//! integers big-endian fixed width; uint256/hashes in their canonical
//! serialized byte order. These bytes are what gets BLS-signed (with the
//! DST prepended by the signing wrapper) and what the Ethereum light
//! client reconstructs — do not change without regenerating the shared
//! test vectors.

//! 144 bytes: chain_id ‖ epoch ‖ block_hash ‖ height ‖ committee_root ‖ pegout_root
std::vector<unsigned char> CheckpointBytes(
    const uint256& chain_id,
    uint64_t epoch,
    const uint256& block_hash,
    uint64_t height,
    const uint256& committee_root,
    const uint256& pegout_root);

//! 132 bytes: chain_id ‖ eth_chain_id ‖ deposit_id ‖ token(20) ‖ amount ‖ claim_commit
std::vector<unsigned char> AttestationBytes(
    const uint256& chain_id,
    uint64_t eth_chain_id,
    const uint256& deposit_id,
    const std::vector<unsigned char>& token, // 20 bytes (ERC20 address)
    uint64_t amount,
    const uint256& claim_commit);

//! 97 bytes: chain_id ‖ challenge_txid ‖ deposit_id ‖ verdict(1=uphold, 0=reject)
std::vector<unsigned char> ResolutionBytes(
    const uint256& chain_id,
    const uint256& challenge_txid,
    const uint256& deposit_id,
    uint8_t verdict);

//! Message a guardian's proof of possession signs: DST_POP handling is in
//! the signing wrapper; the message body is the serialized public key.
//! (Kept as a helper for symmetry/testability.)
std::vector<unsigned char> PopBytes(const std::vector<unsigned char>& pk_g);

//! Wrapped-asset token id preimage: SHA256("nbp/v1" ‖ eth_chain_id ‖ erc20_address)
uint256 BridgeTokenId(uint64_t eth_chain_id, const std::vector<unsigned char>& token);

//! PegOut Merkle leaf (§3.4): txid ‖ token_id ‖ amount ‖ eth_recipient(20) ‖ out_index
std::vector<unsigned char> PegOutLeaf(
    const uint256& txid,
    const uint256& token_id,
    uint64_t amount,
    const std::vector<unsigned char>& eth_recipient,
    uint32_t out_index);

//! Committee Merkle leaf (§3.4): pk_g(48, compressed) ‖ bond(u64 BE)
std::vector<unsigned char> CommitteeLeaf(const std::vector<unsigned char>& pk_g, uint64_t bond);

} // namespace nbp

#endif // NAVIO_BLSCT_BRIDGE_MESSAGES_H
