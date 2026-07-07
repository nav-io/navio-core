// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/bridge/merkle.h>

#include <crypto/sha256.h>

namespace nbp {

static uint256 Sha256Tagged(uint8_t tag, const unsigned char* d1, size_t n1, const unsigned char* d2 = nullptr, size_t n2 = 0)
{
    uint256 out;
    CSHA256 hasher;
    hasher.Write(&tag, 1);
    if (n1 > 0) hasher.Write(d1, n1);
    if (n2 > 0) hasher.Write(d2, n2);
    hasher.Finalize(out.begin());
    return out;
}

uint256 MerkleLeafHash(const std::vector<unsigned char>& leaf)
{
    return Sha256Tagged(0x00, leaf.data(), leaf.size());
}

uint256 MerkleInnerHash(const uint256& left, const uint256& right)
{
    return Sha256Tagged(0x01, left.begin(), 32, right.begin(), 32);
}

uint256 MerkleEmptyRoot()
{
    return Sha256Tagged(0x02, nullptr, 0);
}

uint256 ComputeMerkleRootFromHashes(std::vector<uint256> hashes)
{
    if (hashes.empty()) return MerkleEmptyRoot();
    while (hashes.size() > 1) {
        std::vector<uint256> next;
        next.reserve((hashes.size() + 1) / 2);
        for (size_t i = 0; i + 1 < hashes.size(); i += 2) {
            next.push_back(MerkleInnerHash(hashes[i], hashes[i + 1]));
        }
        if (hashes.size() % 2 == 1) next.push_back(hashes.back());
        hashes = std::move(next);
    }
    return hashes[0];
}

uint256 ComputeMerkleRoot(const std::vector<std::vector<unsigned char>>& leaves)
{
    std::vector<uint256> hashes;
    hashes.reserve(leaves.size());
    for (const auto& leaf : leaves) {
        hashes.push_back(MerkleLeafHash(leaf));
    }
    return ComputeMerkleRootFromHashes(std::move(hashes));
}

MerkleProof ComputeMerkleProof(const std::vector<std::vector<unsigned char>>& leaves, size_t index)
{
    MerkleProof proof;
    if (index >= leaves.size()) return proof;
    std::vector<uint256> level;
    level.reserve(leaves.size());
    for (const auto& leaf : leaves) {
        level.push_back(MerkleLeafHash(leaf));
    }
    size_t pos = index;
    while (level.size() > 1) {
        if (pos % 2 == 0) {
            if (pos + 1 < level.size()) {
                proof.hashes.push_back(level[pos + 1]);
                proof.directions.push_back(0x00);
            }
            // else: odd node promoted, no sibling this level
        } else {
            proof.hashes.push_back(level[pos - 1]);
            proof.directions.push_back(0x01);
        }
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i + 1 < level.size(); i += 2) {
            next.push_back(MerkleInnerHash(level[i], level[i + 1]));
        }
        if (level.size() % 2 == 1) next.push_back(level.back());
        level = std::move(next);
        pos /= 2;
    }
    return proof;
}

bool VerifyMerkleProof(const uint256& root, const std::vector<unsigned char>& leaf, const MerkleProof& proof)
{
    if (proof.hashes.size() != proof.directions.size()) return false;
    uint256 acc = MerkleLeafHash(leaf);
    for (size_t i = 0; i < proof.hashes.size(); ++i) {
        if (proof.directions[i] == 0x00) {
            acc = MerkleInnerHash(acc, proof.hashes[i]);
        } else if (proof.directions[i] == 0x01) {
            acc = MerkleInnerHash(proof.hashes[i], acc);
        } else {
            return false;
        }
    }
    return acc == root;
}

} // namespace nbp
