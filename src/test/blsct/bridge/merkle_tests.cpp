// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/bridge/merkle.h>
#include <blsct/bridge/messages.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace nbp;

BOOST_FIXTURE_TEST_SUITE(nbp_merkle_tests, BasicTestingSetup)

static std::vector<unsigned char> Leaf(const std::string& s)
{
    return std::vector<unsigned char>(s.begin(), s.end());
}

BOOST_AUTO_TEST_CASE(empty_and_single)
{
    BOOST_CHECK(ComputeMerkleRoot({}) == MerkleEmptyRoot());
    // Single leaf: root == leaf hash (promoted).
    auto l = Leaf("a");
    BOOST_CHECK(ComputeMerkleRoot({l}) == MerkleLeafHash(l));
    // Leaf hash is domain-separated from a plain SHA256.
    BOOST_CHECK(MerkleLeafHash(l) != MerkleEmptyRoot());
}

BOOST_AUTO_TEST_CASE(roots_sizes_2_to_5)
{
    std::vector<std::vector<unsigned char>> leaves;
    for (int n = 2; n <= 5; n++) {
        leaves.clear();
        for (int i = 0; i < n; i++) {
            leaves.push_back(Leaf("leaf-" + std::to_string(i)));
        }
        const uint256 root = ComputeMerkleRoot(leaves);
        BOOST_CHECK(root != MerkleEmptyRoot());
        // Every leaf must have a verifying proof; wrong leaf must fail.
        for (int i = 0; i < n; i++) {
            const auto proof = ComputeMerkleProof(leaves, i);
            BOOST_CHECK_MESSAGE(VerifyMerkleProof(root, leaves[i], proof), "n=" << n << " i=" << i);
            BOOST_CHECK(!VerifyMerkleProof(root, Leaf("not-a-leaf"), proof));
        }
        // Proof for one index must not verify at a sibling's leaf.
        const auto proof0 = ComputeMerkleProof(leaves, 0);
        BOOST_CHECK(!VerifyMerkleProof(root, leaves[1], proof0));
    }
}

BOOST_AUTO_TEST_CASE(odd_promotion_asymmetry)
{
    // With 3 leaves, [a,b,c] != [a,c,b]: ordering matters, promotion is
    // position-dependent.
    auto a = Leaf("a"), b = Leaf("b"), c = Leaf("c");
    BOOST_CHECK(ComputeMerkleRoot({a, b, c}) != ComputeMerkleRoot({a, c, b}));
    // Duplicate-last attack shape: [a,b] root must differ from [a,b,b].
    BOOST_CHECK(ComputeMerkleRoot({a, b}) != ComputeMerkleRoot({a, b, b}));
}

BOOST_AUTO_TEST_CASE(message_layout_sizes)
{
    const uint256 h1{uint64_t{1}}, h2{uint64_t{2}}, h3{uint64_t{3}}, h4{uint64_t{4}};
    std::vector<unsigned char> addr20(20, 0xaa);
    BOOST_CHECK_EQUAL(CheckpointBytes(h1, 7, h2, 42, h3, h4).size(), 144U);
    BOOST_CHECK_EQUAL(AttestationBytes(h1, 1, h2, addr20, 5, h3).size(), 132U);
    BOOST_CHECK_EQUAL(ResolutionBytes(h1, h2, h3, 1).size(), 97U);

    // Big-endian integer placement: epoch=7 occupies bytes [32,40) of cp_bytes.
    auto cp = CheckpointBytes(h1, 7, h2, 42, h3, h4);
    for (int i = 32; i < 39; i++) BOOST_CHECK_EQUAL(cp[i], 0);
    BOOST_CHECK_EQUAL(cp[39], 7);

    // Token id derivation is deterministic and chain-id sensitive.
    BOOST_CHECK(BridgeTokenId(1, addr20) == BridgeTokenId(1, addr20));
    BOOST_CHECK(BridgeTokenId(1, addr20) != BridgeTokenId(2, addr20));
}

BOOST_AUTO_TEST_SUITE_END()
