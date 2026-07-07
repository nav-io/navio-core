// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BRIDGE_MERKLE_H
#define NAVIO_BLSCT_BRIDGE_MERKLE_H

#include <uint256.h>

#include <vector>

namespace nbp {

//! Domain-separated binary Merkle tree shared byte-for-byte with the
//! Ethereum light client and the Python tooling (navio-bridge-protocol
//! IMPLEMENTATION.md §3.4):
//!   leaf  = SHA256(0x00 ‖ leaf_bytes)
//!   inner = SHA256(0x01 ‖ left ‖ right)
//!   an odd node is promoted unhashed to the next level
//!   empty tree root = SHA256(0x02)
uint256 MerkleLeafHash(const std::vector<unsigned char>& leaf);
uint256 MerkleInnerHash(const uint256& left, const uint256& right);
uint256 MerkleEmptyRoot();

//! Root over already-leaf-hashed nodes.
uint256 ComputeMerkleRootFromHashes(std::vector<uint256> hashes);

//! Root over raw leaves (applies MerkleLeafHash first).
uint256 ComputeMerkleRoot(const std::vector<std::vector<unsigned char>>& leaves);

//! Membership proof (sibling hashes bottom-up) for the leaf at `index`.
//! Because odd nodes are promoted, a level can contribute no sibling; the
//! proof therefore carries one direction byte per step: 0x00 = sibling is
//! on the right, 0x01 = sibling is on the left.
struct MerkleProof {
    std::vector<uint256> hashes;
    std::vector<uint8_t> directions;
};
MerkleProof ComputeMerkleProof(const std::vector<std::vector<unsigned char>>& leaves, size_t index);
bool VerifyMerkleProof(const uint256& root, const std::vector<unsigned char>& leaf, const MerkleProof& proof);

} // namespace nbp

#endif // NAVIO_BLSCT_BRIDGE_MERKLE_H
