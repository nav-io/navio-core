// Copyright (c) 2022 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/arith/mcl/mcl.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>
#include <streams.h>

#include <functional>
#include <string>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(bulletproofs_plus_range_proof_tests, BasicTestingSetup)

using T = Mcl;
using Point = T::Point;
using Scalar = T::Scalar;
using Points = Elements<Point>;

bulletproofs_plus::RangeProof<T> GenProof() {
    Point g = Point::GetBasePoint();

    Points Vs;
    Vs.Add(g * 100);
    Vs.Add(g * 101);

    Points Ls;
    Ls.Add(g * 200);
    Ls.Add(g * 201);

    Points Rs;
    Rs.Add(g * 300);
    Rs.Add(g * 301);

    Point A = g * 2;
    Point A_wip = g * 3;
    Point B = g * 4;

    Scalar r_prime(2);
    Scalar s_prime(3);
    Scalar delta_prime(4);
    Scalar alpha_hat(5);
    Scalar tau_x(6);

    bulletproofs_plus::RangeProof<T> p;
    {
        p.Vs = Vs;
        p.Ls = Ls;
        p.Rs = Rs;

        p.A = A;
        p.A_wip = A_wip;
        p.B = B;

        p.r_prime = r_prime;
        p.s_prime = s_prime;
        p.delta_prime = delta_prime;
        p.alpha_hat = alpha_hat;
        p.tau_x = tau_x;
    }

    return p;
}

BOOST_AUTO_TEST_CASE(test_equal)
{
    auto p = GenProof();
    auto q = GenProof();
    BOOST_CHECK(p == p);

    q.A = q.A + q.A;

    BOOST_CHECK(p != q);
}

// Every field Serialize() writes has to take part in equality, otherwise two
// proofs that serialize to different bytes compare equal.
BOOST_AUTO_TEST_CASE(test_equal_covers_serialized_fields)
{
    const auto p = GenProof();

    const std::vector<std::pair<std::string, std::function<void(bulletproofs_plus::RangeProof<T>&)>>> mutations = {
        {"Vs", [](auto& q) { q.Vs.Add(Point::GetBasePoint()); }},
        {"Ls", [](auto& q) { q.Ls.Add(Point::GetBasePoint()); }},
        {"Rs", [](auto& q) { q.Rs.Add(Point::GetBasePoint()); }},
        {"A", [](auto& q) { q.A = q.A + q.A; }},
        {"A_wip", [](auto& q) { q.A_wip = q.A_wip + q.A_wip; }},
        {"B", [](auto& q) { q.B = q.B + q.B; }},
        {"r_prime", [](auto& q) { q.r_prime = q.r_prime + Scalar(1); }},
        {"s_prime", [](auto& q) { q.s_prime = q.s_prime + Scalar(1); }},
        {"delta_prime", [](auto& q) { q.delta_prime = q.delta_prime + Scalar(1); }},
        {"alpha_hat", [](auto& q) { q.alpha_hat = q.alpha_hat + Scalar(1); }},
        {"tau_x", [](auto& q) { q.tau_x = q.tau_x + Scalar(1); }},
    };

    DataStream st_p{};
    p.Serialize(st_p);

    for (const auto& [name, mutate] : mutations) {
        auto q = GenProof();
        mutate(q);

        DataStream st_q{};
        q.Serialize(st_q);
        BOOST_CHECK_MESSAGE(st_p.str() != st_q.str(),
                            "mutating " + name + " did not change the serialization");

        BOOST_CHECK_MESSAGE(p != q, "proofs differing in " + name + " compare equal");
    }
}

BOOST_AUTO_TEST_CASE(test_de_ser)
{
    auto p = GenProof();

    DataStream st{};
    p.Serialize(st);

    bulletproofs_plus::RangeProof<T> q;
    q.Unserialize(st);

    BOOST_CHECK(p == q);
}


BOOST_AUTO_TEST_CASE(test_de_ser_rejects_oversized_or_mismatched_vectors)
{
    // Vs is bounded by the maximum number of input values, Ls/Rs by the
    // maximum number of inner-product rounds, and |Ls| == |Rs|. Each bound is
    // enforced at the length prefix, before any element is decoded.
    auto p = GenProof();
    BOOST_REQUIRE(p.Vs.Size() > 0);
    const Point g = Point::GetBasePoint();

    {
        auto q = p;
        q.Ls.Add(g);
        DataStream st{};
        q.Serialize(st);
        bulletproofs_plus::RangeProof<T> r;
        BOOST_CHECK_THROW(r.Unserialize(st), std::ios_base::failure);
    }
    {
        auto q = p;
        q.Ls.Clear();
        q.Rs.Clear();
        for (uint64_t i = 0; i <= range_proof::ProofBase<T>::MAX_ROUNDS; ++i) {
            q.Ls.Add(g);
            q.Rs.Add(g);
        }
        DataStream st{};
        q.Serialize(st);
        bulletproofs_plus::RangeProof<T> r;
        BOOST_CHECK_THROW(r.Unserialize(st), std::ios_base::failure);
    }
    {
        auto q = p;
        q.Vs.Clear();
        for (uint64_t i = 0; i <= range_proof::ProofBase<T>::MAX_VS; ++i) q.Vs.Add(g);
        DataStream st{};
        q.Serialize(st);
        bulletproofs_plus::RangeProof<T> r;
        BOOST_CHECK_THROW(r.Unserialize(st), std::ios_base::failure);
    }
    {
        // Oversized length prefix with nothing behind it. Two traps here:
        // a count above MAX_SIZE is rejected by ReadCompactSize before this
        // bound is consulted at all, and an exhausted stream raises the same
        // exception type -- so a bare BOOST_CHECK_THROW on a huge prefix
        // passes with or without the bound, for the wrong reason. Use a count
        // that ReadCompactSize accepts but the protocol maximum does not, and
        // assert the failure came from the length-prefix check.
        DataStream st{};
        ::WriteCompactSize(st, uint64_t{1000});
        bulletproofs_plus::RangeProof<T> r;
        BOOST_CHECK_EXCEPTION(r.Unserialize(st), std::ios_base::failure,
                              [](const std::ios_base::failure& e) {
                                  return std::string(e.what()).find("exceeds protocol maximum") != std::string::npos;
                              });
    }
}

BOOST_AUTO_TEST_SUITE_END()
