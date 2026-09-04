// Copyright (c) 2023-2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_UNIT_TEST

#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/elements.h>
#include <blsct/set_mem_proof/set_mem_proof.h>
#include <streams.h>
#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

#include <string>

using Scalar = Mcl::Scalar;
using Point = Mcl::Point;
using Points = Elements<Point>;

BOOST_FIXTURE_TEST_SUITE(set_mem_proof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_equal)
{
    Point g = Point::GetBasePoint();

    Point phi = g;
    Point A1 = g * 2;
    Point A2 = g * 3;
    Point S1 = g * 4;
    Point S2 = g * 5;
    Point S3 = g * 6;
    Point T1 = g * 7;
    Point T2 = g * 8;
    Scalar tau_x(1);
    Scalar mu(2);
    Scalar z_alpha(3);
    Scalar z_tau(4);
    Scalar z_beta(5);
    Scalar t(6);
    Points Ls;
    Ls.Add(g * 100);
    Ls.Add(g * 101);
    Points Rs;
    Rs.Add(g * 200);
    Rs.Add(g * 201);
    Scalar a(7);
    Scalar b(8);
    Scalar omega(9);

    auto p = SetMemProof<Mcl>(
        phi,
        A1,
        A2,
        S1,
        S2,
        S3,
        T1,
        T2,
        tau_x,
        mu,
        z_alpha,
        z_tau,
        z_beta,
        t,
        Ls,
        Rs,
        a,
        b,
        omega
    );

    auto q = SetMemProof<Mcl>(
        phi,
        g,
        A2,
        S1,
        S2,
        S3,
        T1,
        T2,
        tau_x,
        mu,
        z_alpha,
        z_tau,
        z_beta,
        t,
        Ls,
        Rs,
        a,
        b,
        omega
    );

    BOOST_CHECK(p == p);
    BOOST_CHECK(p != q);
}

BOOST_AUTO_TEST_CASE(test_de_ser)
{
    Point g = Point::GetBasePoint();

    Point phi = g;
    Point A1 = g * 2;
    Point A2 = g * 3;
    Point S1 = g * 4;
    Point S2 = g * 5;
    Point S3 = g * 6;
    Point T1 = g * 7;
    Point T2 = g * 8;
    Scalar tau_x(1);
    Scalar mu(2);
    Scalar z_alpha(3);
    Scalar z_tau(4);
    Scalar z_beta(5);
    Scalar t(6);
    Points Ls;
    Ls.Add(g * 100);
    Ls.Add(g * 101);
    Points Rs;
    Rs.Add(g * 200);
    Rs.Add(g * 201);
    Scalar a(7);
    Scalar b(8);
    Scalar omega(9);

    auto p = SetMemProof<Mcl>(
        phi,
        A1,
        A2,
        S1,
        S2,
        S3,
        T1,
        T2,
        tau_x,
        mu,
        z_alpha,
        z_tau,
        z_beta,
        t,
        Ls,
        Rs,
        a,
        b,
        omega
    );

    DataStream st{};
    p.Serialize(st);

    SetMemProof<Mcl> q;
    q.Unserialize(st);

    BOOST_CHECK(p  == q);
}


BOOST_AUTO_TEST_CASE(test_de_ser_rejects_malformed_ls_rs)
{
    // |Ls| must equal |Rs| and both are bounded by the maximum ring size
    // (log2(N) rounds); a stream violating either is rejected at the length
    // prefix, before any point is decoded.
    Point g = Point::GetBasePoint();
    auto make = [&](size_t n_ls, size_t n_rs) {
        Points Ls, Rs;
        for (size_t i = 0; i < n_ls; ++i) Ls.Add(g * static_cast<int64_t>(100 + i));
        for (size_t i = 0; i < n_rs; ++i) Rs.Add(g * static_cast<int64_t>(200 + i));
        return SetMemProof<Mcl>(g, g * 2, g * 3, g * 4, g * 5, g * 6, g * 7, g * 8,
                                Scalar(1), Scalar(2), Scalar(3), Scalar(4), Scalar(5), Scalar(6),
                                Ls, Rs, Scalar(7), Scalar(8), Scalar(9));
    };
    // Well-formed: round-trips.
    {
        auto p = make(3, 3);
        DataStream st{};
        p.Serialize(st);
        SetMemProof<Mcl> q;
        q.Unserialize(st);
        BOOST_CHECK(p == q);
    }
    // Mismatched sizes.
    {
        auto p = make(3, 2);
        DataStream st{};
        p.Serialize(st);
        SetMemProof<Mcl> q;
        BOOST_CHECK_THROW(q.Unserialize(st), std::ios_base::failure);
    }
    // More rounds than the largest ring allows.
    {
        const size_t too_many = SetMemProof<Mcl>::MAX_ROUNDS + 1;
        auto p = make(too_many, too_many);
        DataStream st{};
        p.Serialize(st);
        SetMemProof<Mcl> q;
        BOOST_CHECK_THROW(q.Unserialize(st), std::ios_base::failure);
    }
    // A length prefix beyond the bound, with no element bytes behind it, is
    // rejected without attempting to read (or allocate) anything. The count
    // must stay under MAX_SIZE or ReadCompactSize rejects it before this
    // bound is reached, and an exhausted stream raises the same exception
    // type -- so assert on the message, or the case passes either way.
    {
        DataStream st{};
        SetMemProof<Mcl> hdr = make(0, 0);
        st << hdr.phi << hdr.A1 << hdr.A2 << hdr.S1 << hdr.S2 << hdr.S3 << hdr.T1 << hdr.T2
           << hdr.tau_x << hdr.mu << hdr.z_alpha << hdr.z_tau << hdr.z_beta << hdr.t;
        ::WriteCompactSize(st, uint64_t{1000});
        SetMemProof<Mcl> q;
        BOOST_CHECK_EXCEPTION(q.Unserialize(st), std::ios_base::failure,
                              [](const std::ios_base::failure& e) {
                                  return std::string(e.what()).find("exceeds protocol maximum") != std::string::npos;
                              });
    }
}

BOOST_AUTO_TEST_SUITE_END()
