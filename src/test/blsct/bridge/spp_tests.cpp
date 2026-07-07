// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/bridge/spp.h>
#include <blsct/range_proof/generators.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using Arith = Mcl;
using Point = Arith::Point;
using Scalar = Arith::Scalar;

BOOST_FIXTURE_TEST_SUITE(nbp_spp_tests, BasicTestingSetup)

namespace {
// Build a staked-commitment point for value v with blinding f under the
// default-token generators (matches how ProveStake forms sigma).
Point Commit(const Scalar& v, const Scalar& f)
{
    range_proof::GeneratorsFactory<Arith> gf;
    range_proof::Generators<Arith> gen = gf.GetInstance(TokenId());
    return gen.G * v + gen.H * f;
}
} // namespace

BOOST_AUTO_TEST_CASE(prove_and_verify_sum_meets_bond)
{
    const uint64_t period = 7;
    std::vector<std::pair<Scalar, Scalar>> owned;
    std::vector<Point> stakedSet;

    // Three owned coins summing to 900; plus decoys in the set.
    const std::vector<int64_t> vals{500, 300, 100};
    for (int64_t v : vals) {
        Scalar sv(v), sf = Scalar::Rand();
        owned.emplace_back(sv, sf);
        stakedSet.push_back(Commit(sv, sf));
    }
    for (int i = 0; i < 5; i++) stakedSet.push_back(Commit(Scalar(1000 + i), Scalar::Rand()));

    auto proof = nbp::ProveStake(stakedSet, owned, /*bond=*/900, period);
    BOOST_REQUIRE(proof.has_value());

    std::vector<uint256> tags;
    std::string err;
    BOOST_CHECK_MESSAGE(nbp::VerifyStakeProof(stakedSet, 900, period, *proof, tags, err), err);
    BOOST_CHECK_EQUAL(tags.size(), owned.size());

    // The bond is fixed at proof time (Bulletproofs+ min-value is exact): a
    // proof for bond 900 does NOT verify against a different bond.
    BOOST_CHECK(!nbp::VerifyStakeProof(stakedSet, 800, period, *proof, tags, err));
}

BOOST_AUTO_TEST_CASE(bond_above_stake_fails)
{
    const uint64_t period = 1;
    std::vector<std::pair<Scalar, Scalar>> owned;
    std::vector<Point> stakedSet;
    Scalar v(100), f = Scalar::Rand();
    owned.emplace_back(v, f);
    stakedSet.push_back(Commit(v, f));

    // Proving sum >= 500 with only 100 staked must fail range verification.
    auto proof = nbp::ProveStake(stakedSet, owned, /*bond=*/500, period);
    if (proof) {
        std::vector<uint256> tags;
        std::string err;
        BOOST_CHECK(!nbp::VerifyStakeProof(stakedSet, 500, period, *proof, tags, err));
    }
}

BOOST_AUTO_TEST_CASE(wrong_period_fails)
{
    std::vector<std::pair<Scalar, Scalar>> owned;
    std::vector<Point> stakedSet;
    Scalar v(1000), f = Scalar::Rand();
    owned.emplace_back(v, f);
    stakedSet.push_back(Commit(v, f));
    for (int i = 0; i < 6; i++) stakedSet.push_back(Commit(Scalar(1234 + i), Scalar::Rand()));

    auto proof = nbp::ProveStake(stakedSet, owned, 1000, /*period=*/3);
    BOOST_REQUIRE(proof.has_value());
    std::vector<uint256> tags;
    std::string err;
    // Verifying under a different period uses different generators, so both
    // the membership and range checks fail.
    BOOST_CHECK(!nbp::VerifyStakeProof(stakedSet, 1000, /*period=*/4, *proof, tags, err));
    // Correct period verifies.
    std::string err2;
    BOOST_CHECK_MESSAGE(nbp::VerifyStakeProof(stakedSet, 1000, 3, *proof, tags, err2), err2);
}

BOOST_AUTO_TEST_CASE(coin_not_in_set_fails)
{
    const uint64_t period = 2;
    std::vector<std::pair<Scalar, Scalar>> owned;
    Scalar v(1000), f = Scalar::Rand();
    owned.emplace_back(v, f);

    // Set does NOT contain the owned coin.
    std::vector<Point> stakedSet;
    for (int i = 0; i < 4; i++) stakedSet.push_back(Commit(Scalar(1000 + i), Scalar::Rand()));

    auto proof = nbp::ProveStake(stakedSet, owned, 1000, period);
    // Prove may succeed structurally, but verification must reject membership.
    if (proof) {
        std::vector<uint256> tags;
        std::string err;
        BOOST_CHECK(!nbp::VerifyStakeProof(stakedSet, 1000, period, *proof, tags, err));
    }
}

BOOST_AUTO_TEST_SUITE_END()
