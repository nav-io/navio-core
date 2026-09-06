// Copyright (c) 2022 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#include <algorithm>
#include <blsct/arith/elements.h>
#include <blsct/arith/blst/blst_g1point.h>
#include <blsct/arith/blst/blst_scalar.h>
#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <limits>
#include <set>
#include <stdexcept>
#include <streams.h>
#include <string>
#include <utility>

BOOST_FIXTURE_TEST_SUITE(elements_tests, BasicTestingSetup)

using Point = BlstG1Point;
using Scalar = BlstScalar;
using Points = Elements<Point>;
using OrderedPoints = OrderedElements<Point>;
using Scalars = Elements<Scalar>;

BOOST_AUTO_TEST_CASE(test_constructors)
{
    {
        Scalars ss(std::vector<Scalar> { Scalar{1}, Scalar{2} });
        BOOST_CHECK(ss.Size() == 2);
        BOOST_CHECK(ss[0].GetUint64() == 1);
        BOOST_CHECK(ss[1].GetUint64() == 2);
    }
    {
        Scalar s(2);
        Scalars ss(3, s);
        BOOST_CHECK(ss.Size() == 3);
        BOOST_CHECK(ss[0].GetUint64() == 2);
        BOOST_CHECK(ss[1].GetUint64() == 2);
        BOOST_CHECK(ss[2].GetUint64() == 2);
    }
    {
        auto g = Point::GetBasePoint();
        Points g1s(2, g);
        BOOST_CHECK(g1s.Size() == 2);
        BOOST_CHECK(g1s[0] == g);
        BOOST_CHECK(g1s[1] == g);
    }
    {
        auto g = Point::GetBasePoint();
        auto g2 = g + g;
        Points g1s(std::vector<Point> { g, g2 });
        BOOST_CHECK(g1s.Size() == 2);
        BOOST_CHECK(g1s[0] == g);
        BOOST_CHECK(g1s[1] == g2);
    }
}

BOOST_AUTO_TEST_CASE(test_size)
{
    {
        Scalars ss(std::vector<Scalar> { Scalar{1}, Scalar{2} });
        BOOST_CHECK(ss.Size() == 2);
    }
    {
        Scalars ss;
        BOOST_CHECK(ss.Size() == 0);
    }
    {
        auto g = Point::GetBasePoint();
        Points g1s(std::vector<Point> { g, g + g });
        BOOST_CHECK(g1s.Size() == 2);
    }
    {
        Points g1s;
        BOOST_CHECK(g1s.Size() == 0);
    }
}

BOOST_AUTO_TEST_CASE(test_empty)
{
    {
        Scalars ss(std::vector<Scalar> { Scalar{1}, Scalar{2} });
        BOOST_CHECK(ss.Empty() == false);
    }
    {
        Scalars ss;
        BOOST_CHECK(ss.Empty() == true);
    }
    {
        auto g = Point::GetBasePoint();
        Points g1s(std::vector<Point> { g, g + g });
        BOOST_CHECK(g1s.Empty() == false);
    }
    {
        Points g1s;
        BOOST_CHECK(g1s.Empty() == true);
    }
}

BOOST_AUTO_TEST_CASE(test_sum)
{
    {
        Scalars ss(std::vector<Scalar> { Scalar{1}, Scalar{2} });
        auto sum = ss.Sum();
        BOOST_CHECK_EQUAL(sum.GetUint64(), 3);
    }
    {
        Scalars ss;
        auto sum = ss.Sum();
        BOOST_CHECK_EQUAL(sum.GetUint64(), 0);
    }
    {
        auto g = Point::GetBasePoint();
        Points g1s(std::vector<Point> { g, g + g });
        auto sum = g1s.Sum();
        BOOST_CHECK(sum == (g * 3));
    }
    {
        Points g1s;
        auto sum = g1s.Sum();
        Point g;
        BOOST_CHECK(sum == g);
    }
}

BOOST_AUTO_TEST_CASE(test_add)
{
    {
        Scalars ss;
        Scalar x(1);
        ss.Add(x);
        BOOST_CHECK(ss.Size() == 1);
        BOOST_CHECK(ss[0].GetUint64() == 1);
    }
    {
        Points g1s;
        auto g = Point::GetBasePoint();
        g1s.Add(g);
        BOOST_CHECK(g1s.Size() == 1);
        BOOST_CHECK(g1s[0] == g);
    }
}

BOOST_AUTO_TEST_CASE(test_confirm_sizes_match)
{
    {
        Scalars s1(std::vector<Scalar> { Scalar{1} });
        Scalars s2(std::vector<Scalar>{ Scalar{1}, Scalar{2} });
        BOOST_CHECK_THROW(s1.ConfirmSizesMatch(s2.Size()), std::runtime_error);
    }
    {
        Scalars s1(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        Scalars s2(std::vector<Scalar>{ Scalar{1}, Scalar{2} });
        BOOST_CHECK_NO_THROW(s1.ConfirmSizesMatch(s2.Size()));
    }
    {
        auto g = Point::GetBasePoint();
        Points gg(std::vector<Point> { g, g + g });
        Points hh(std::vector<Point>{ g });
        BOOST_CHECK_THROW(gg.ConfirmSizesMatch(hh.Size()), std::runtime_error);
    }
    {
        auto g = Point::GetBasePoint();
        Points gg(std::vector<Point> { g, g + g });
        Points hh(std::vector<Point>{ g, g * 3 });
        BOOST_CHECK_NO_THROW(gg.ConfirmSizesMatch(hh.Size()));
    }
}

BOOST_AUTO_TEST_CASE(test_operator_mul_scalars)
{
    // Points ^ Scalars -> Points
    {
        Scalars ss(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        auto g = Point::GetBasePoint();
        Points gg(std::vector<Point> { g, g + g });
        auto hh = gg * ss;

        auto h1 = g * Scalar(2);
        auto h2 = (g + g) * Scalar(3);
        Points ii(std::vector<Point> { h1, h2 });

        BOOST_CHECK(hh == ii);
    }
    // Scalars ^ Scalars -> Scalars
    {
        Scalars ss(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        Scalars tt(std::vector<Scalar>{ Scalar{3}, Scalar{4} });
        auto uu = ss * tt;

        Scalars vv(std::vector<Scalar> { Scalar{6}, Scalar{12} });

        BOOST_CHECK(uu == vv);
    }
}

BOOST_AUTO_TEST_CASE(test_operator_mul_scalar)
{
    // Scalars * Scalar -> Scalars
    {
        Scalars ss(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        Scalar z(5);
        auto r1 = ss * z;

        auto zz = Scalars::RepeatN(z, ss.Size());
        auto r2 = ss * zz;

        BOOST_CHECK(r1 == r2);
    }
    // Points * Scalar -> Points
    {
        auto g = Point::GetBasePoint();
        Points gg(std::vector<Point> { g, g + g });
        Scalar z(3);
        auto r1 = gg * z;

        auto zz = Scalars::RepeatN(z, gg.Size());
        auto r2 = gg * zz;

        BOOST_CHECK(r1 == r2);
    }
}

BOOST_AUTO_TEST_CASE(test_operator_add)
{
    {
        Scalars ss(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        Scalars tt(std::vector<Scalar>{ Scalar{3}, Scalar{4} });
        auto uu = ss + tt;

        Scalars vv(std::vector<Scalar> { Scalar{5}, Scalar{7} });
        BOOST_CHECK(uu == vv);
    }
    {
        auto g = Point::GetBasePoint();
        Points gg(std::vector<Point> { g, g + g });
        Points hh(std::vector<Point>{ g + g, g });
        auto ii = gg + hh;

        Points jj(std::vector<Point> { g + g + g, g + g + g });
        BOOST_CHECK(ii == jj);
    }
}

BOOST_AUTO_TEST_CASE(test_operator_sub)
{
    {
        Scalars ss(std::vector<Scalar> { Scalar{7}, Scalar{6} });
        Scalars tt(std::vector<Scalar> { Scalar{3}, Scalar{4} });
        auto uu = ss - tt;

        Scalars vv(std::vector<Scalar> { Scalar{4}, Scalar{2} });
        BOOST_CHECK(uu == vv);
    }
    {
        auto g = Point::GetBasePoint();
        Points gg(std::vector<Point> { g + g + g, g + g + g + g });
        Points hh(std::vector<Point> { g, g });
        auto ii = gg - hh;

        Points jj(std::vector<Point> { g + g, g + g + g });
        BOOST_CHECK(ii == jj);
    }
}

BOOST_AUTO_TEST_CASE(test_operator_assign)
{
    {
        Scalars a(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        Scalars b;
        b = a;
        BOOST_CHECK(b.Size() == 2);
        BOOST_CHECK(b[0].GetUint64() == 2);
        BOOST_CHECK(b[1].GetUint64() == 3);
    }
    {
        auto g = Point::GetBasePoint();
        auto g2 = g + g;
        Points gs(std::vector<Point> { g, g2 });
        Points gs2;
        gs2 = gs;
        BOOST_CHECK(gs2.Size() == 2);
        BOOST_CHECK(gs2[0] == g);
        BOOST_CHECK(gs2[1] == g2);
    }
}

BOOST_AUTO_TEST_CASE(test_operator_eq)
{
    {
        Scalars ss(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        Scalars tt(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        auto b = ss == tt;
        BOOST_CHECK(b);
    }
    {
        auto g = Point::GetBasePoint();
        Points gg(std::vector<Point> { g, g + g });
        Points hh(std::vector<Point> { g, g + g });
        auto b = gg == hh;
        BOOST_CHECK(b);
    }
}

BOOST_AUTO_TEST_CASE(test_operator_ne)
{
    {
        Scalars ss(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        Scalars tt(std::vector<Scalar> { Scalar{1}, Scalar{3} });
        auto b = ss != tt;
        BOOST_CHECK(b);
    }
    {
        auto g = Point::GetBasePoint();
        Points gg(std::vector<Point> { g, g + g });
        Points hh(std::vector<Point>{g * 10, g + g});
        auto b = gg != hh;
        BOOST_CHECK(b);
    }
}

BOOST_AUTO_TEST_CASE(test_from)
{
    Scalars ss(std::vector<Scalar> { Scalar{1}, Scalar{2}, Scalar{3} });
    {
        auto tt = ss.From(0);
        BOOST_CHECK(ss == tt);
    }
    {
        auto tt = ss.From(1);
        Scalars uu(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        BOOST_CHECK(tt == uu);
    }
    {
        auto tt = ss.From(2);
        Scalars uu(std::vector<Scalar> { Scalar{3} });
        BOOST_CHECK(tt == uu);
    }
    {
        BOOST_CHECK_THROW(ss.From(3), std::runtime_error);
    }

    auto g = Point::GetBasePoint();
    Points gg(std::vector<Point> { g, g + g, g + g + g });
    {
        auto hh = gg.From(0);
        BOOST_CHECK(gg == hh);
    }
    {
        auto hh = gg.From(1);
        Points ii(std::vector<Point> { g + g, g + g + g });
        BOOST_CHECK(hh == ii);
    }
    {
        auto hh = gg.From(2);
        Points ii(std::vector<Point> { g + g + g });
        BOOST_CHECK(hh == ii);
    }
    {
        BOOST_CHECK_THROW(gg.From(3), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(test_first_n_pow)
{
    {
        Scalar k(3);
        auto pows = Scalars::FirstNPow(k, 3);
        Scalar p1(1);
        Scalar p2(3);
        Scalar p3(9);
        BOOST_CHECK(pows.Size() == 3);
        BOOST_CHECK(pows[0] == p1);
        BOOST_CHECK(pows[1] == p2);
        BOOST_CHECK(pows[2] == p3);
    }
    {
        Scalar k(3);
        auto pows = Scalars::FirstNPow(k, 3, 2);
        Scalar p1(9);
        Scalar p2(27);
        Scalar p3(81);
        BOOST_CHECK(pows.Size() == 3);
        BOOST_CHECK(pows[0] == p1);
        BOOST_CHECK(pows[1] == p2);
        BOOST_CHECK(pows[2] == p3);
    }
    {
        Scalar k(3);
        auto pows = Scalars::FirstNPow(k, 3);
        auto invPows = Scalars::FirstNPow(k.Invert(), 3);
        auto r = pows * invPows;
        Scalar one(1);
        BOOST_CHECK(r[0] == one);
        BOOST_CHECK(r[1] == one);
        BOOST_CHECK(r[2] == one);
    }
    {
        Scalar one(1);
        for(size_t i=0; i<100; ++i) {
            Scalar k(i);
            auto pows = Scalars::FirstNPow(k, 1);
            BOOST_CHECK(pows.Size() == 1);
            BOOST_CHECK(pows[0] == one);
        }
    }
}

BOOST_AUTO_TEST_CASE(test_repeat_n)
{
    Scalar k(3);
    auto pows = Scalars::RepeatN(k, 3);
    BOOST_CHECK(pows.Size() == 3);
    BOOST_CHECK(pows[0] == k);
    BOOST_CHECK(pows[1] == k);
    BOOST_CHECK(pows[2] == k);
}

BOOST_AUTO_TEST_CASE(test_rand_vec)
{
    auto xs = Scalars::RandVec(3);
    BOOST_CHECK(xs.Size() == 3);
}

BOOST_AUTO_TEST_CASE(test_to)
{
    Scalars ss(std::vector<Scalar> { Scalar{1}, Scalar{2}, Scalar{3} });
    {
        auto tt = ss.To(0);
        BOOST_CHECK(tt.Size() == 0);
    }
    {
        auto tt = ss.To(1);
        Scalars uu(std::vector<Scalar> { Scalar{1} });
        BOOST_CHECK(tt == uu);
    }
    {
        auto tt = ss.To(2);
        Scalars uu(std::vector<Scalar> { Scalar{1}, Scalar{2} });
        BOOST_CHECK(tt == uu);
    }
    {
        auto tt = ss.To(3);
        BOOST_CHECK(tt == ss);
    }
    {
        BOOST_CHECK_THROW(ss.To(4), std::runtime_error);
    }

    auto g = Point::GetBasePoint();
    Points gg(std::vector<Point> { g, g + g, g + g + g });
    {
        auto hh = gg.To(0);
        BOOST_CHECK(hh.Size() == 0);
    }
    {
        auto hh = gg.To(1);
        Points ii(std::vector<Point> { g });
        BOOST_CHECK(hh == ii);
    }
    {
        auto hh = gg.To(2);
        Points ii(std::vector<Point> { g, g + g });
        BOOST_CHECK(hh == ii);
    }
    {
        auto hh = gg.To(3);
        Points ii(std::vector<Point> { g, g + g, g + g+ g });
        BOOST_CHECK(hh == ii);
    }
    {
        BOOST_CHECK_THROW(gg.To(4), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(test_negate)
{
    Scalars ss(std::vector<Scalar> { Scalar{1}, Scalar{2} });
    auto ss_inv = ss.Negate();
    BOOST_CHECK(ss_inv[0] == ss[0].Negate());
    BOOST_CHECK(ss_inv[1] == ss[1].Negate());
}

BOOST_AUTO_TEST_CASE(test_invert)
{
    Scalars ss(std::vector<Scalar> { Scalar{1}, Scalar{2} });
    auto ss_inv = ss.Invert();
    BOOST_CHECK(ss_inv[0] == ss[0].Invert());
    BOOST_CHECK(ss_inv[1] == ss[1].Invert());
}

BOOST_AUTO_TEST_CASE(test_reverse)
{
    Scalars ss(std::vector<Scalar> { Scalar{1}, Scalar{2}, Scalar{3} });
    auto ss_rev = ss.Reverse();
    BOOST_CHECK(ss_rev[0] == ss[2]);
    BOOST_CHECK(ss_rev[1] == ss[1]);
    BOOST_CHECK(ss_rev[2] == ss[0]);
}

BOOST_AUTO_TEST_CASE(test_product)
{
    {
        Scalars xs;
        BOOST_CHECK_THROW(xs.Product(), std::runtime_error);
    }
    {
        Scalars xs(std::vector<Scalar> { Scalar{2} });
        Scalar prod = xs.Product();
        BOOST_CHECK(prod.GetUint64() == 2);
    }
    {
        Scalars xs(std::vector<Scalar> { Scalar{2}, Scalar{3} });
        Scalar prod = xs.Product();
        BOOST_CHECK(prod.GetUint64() == 6);
    }
}

BOOST_AUTO_TEST_CASE(test_square)
{
    Scalars ss(std::vector<Scalar> { Scalar{2}, Scalar{3}, Scalar{5} });
    Scalars exp(std::vector<Scalar> { Scalar{4}, Scalar{9}, Scalar{25} });
    auto act = ss.Square();
    BOOST_CHECK(act == exp);
}

BOOST_AUTO_TEST_CASE(test_get_via_index_operator)
{
    {
        Scalar one(1);
        Scalar two(2);
        Scalars xs(std::vector<Scalar> { one, two });
        BOOST_CHECK(xs[0] == one);
        BOOST_CHECK(xs[1] == two);
        BOOST_CHECK_THROW(xs[2], std::runtime_error);
    }
    {
        auto g = Point::GetBasePoint();
        auto g2 = g + g;
        Points xs(std::vector<Point> { g, g2 });
        BOOST_CHECK(xs[0] == g);
        BOOST_CHECK(xs[1] == g2);
        BOOST_CHECK_THROW(xs[2], std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(test_index_operator_rejects_index_wider_than_32_bits)
{
    // 2^32 truncates to 0 in a uint32_t, so a bounds check that narrows the
    // index before comparing it lets the read through and indexes the vector
    // out of bounds. Where size_t is 32 bits wide there is nothing to narrow.
    if constexpr (sizeof(size_t) > sizeof(uint32_t)) {
        // Compute the shift in uint64_t: `if constexpr` in a non-template
        // function does not stop the discarded branch being compiled, so
        // shifting a 32-bit size_t by 32 would be UB if it were ever
        // evaluated. (No diagnostic is emitted today -- verified with gcc and
        // clang at -m32 -Wall -Wextra -- but the branch should not contain a
        // shift that is only well-defined on the platforms that run it.)
        const size_t index = static_cast<size_t>(uint64_t{1} << std::numeric_limits<uint32_t>::digits);
        {
            Scalars xs(std::vector<Scalar> { Scalar{1}, Scalar{2} });
            BOOST_CHECK_THROW(xs[index], std::runtime_error);
            BOOST_CHECK_THROW(std::as_const(xs)[index], std::runtime_error);
        }
        {
            auto g = Point::GetBasePoint();
            Points xs(std::vector<Point> { g, g + g });
            BOOST_CHECK_THROW(xs[index], std::runtime_error);
            BOOST_CHECK_THROW(std::as_const(xs)[index], std::runtime_error);
        }
    }
}

BOOST_AUTO_TEST_CASE(test_index_error_message_on_empty_container)
{
    // size() - 1 underflows when the container is empty, so the old message
    // advertised a range of [0..18446744073709551615] -- the shape that turned
    // up in a testnet staker crash log, where it reads as though the index was
    // inside the range it is being rejected for.
    // Assert on the wording rather than on the absence of SIZE_MAX's digits:
    // the underflowed value differs between 32- and 64-bit size_t, and
    // std::to_string is locale-dependent (test/lint/lint-locale-dependence.py).
    const auto reports_empty = [](const std::runtime_error& e) {
        return std::string(e.what()).find("the container is empty") != std::string::npos;
    };

    {
        Scalars xs;
        BOOST_REQUIRE_EQUAL(xs.Size(), 0);
        BOOST_CHECK_EXCEPTION(xs[0], std::runtime_error, reports_empty);
        BOOST_CHECK_EXCEPTION(std::as_const(xs)[0], std::runtime_error, reports_empty);
    }
    {
        Points xs;
        BOOST_REQUIRE_EQUAL(xs.Size(), 0);
        BOOST_CHECK_EXCEPTION(xs[0], std::runtime_error, reports_empty);
        BOOST_CHECK_EXCEPTION(std::as_const(xs)[0], std::runtime_error, reports_empty);
    }

    // A non-empty container still reports its real upper bound.
    {
        Scalars xs(std::vector<Scalar>{Scalar{1}, Scalar{2}});
        BOOST_CHECK_EXCEPTION(xs[2], std::runtime_error, [](const std::runtime_error& e) {
            return std::string(e.what()).find("[0..1]") != std::string::npos;
        });
    }
}

BOOST_AUTO_TEST_CASE(test_set_via_index_operator)
{
    {
        Scalar one(1);
        Scalar two(2);
        Scalar three(3);
        Scalars xs(2, Scalar(0));
        xs[0] = one;
        xs[1] = two;
        BOOST_CHECK_NO_THROW(xs[0] = one);
        BOOST_CHECK_NO_THROW(xs[1] = two);
        BOOST_CHECK_THROW(xs[2] = three, std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(test_serialize)
{
    {
        Scalar one(1);
        Scalar two(2);

        Scalars xs;
        xs.Add(one);
        xs.Add(two);

        DataStream st{};
        xs.Serialize(st);
        BOOST_CHECK(st.size() == 1 + xs.Size() * sizeof(one.m_scalar));

        Scalars ys;
        ys.Unserialize(st);
        BOOST_CHECK(ys.Size() == 2);
        BOOST_CHECK(ys[0] == one);
        BOOST_CHECK(ys[1] == two);
    }
    {
        Point g = Point::GetBasePoint();
        Point gg = g + g;

        Points xs;
        xs.Add(g);
        xs.Add(gg);

        DataStream st{};
        xs.Serialize(st);

        Points ys;
        ys.Unserialize(st);
        BOOST_CHECK(ys.Size() == 2);
        BOOST_CHECK(ys[0] == g);
        BOOST_CHECK(ys[1] == gg);
    }
}

BOOST_AUTO_TEST_CASE(test_ordered_elements)
{
    OrderedPoints points;

    for (size_t i = 0; i <= 10; i++) {
        points.Add(Point::Rand());
    }

    auto elements = points.GetElements();

    for (size_t i = 0; i <= 9; i++) {
        BOOST_CHECK(elements[i] < elements[i + 1]);
    }

    auto elements_1 = points.GetElements(uint256(uint8_t{10}), 16);
    auto elements_2 = points.GetElements(uint256(uint8_t{10}), 16);
    auto elements_3 = points.GetElements(uint256(uint8_t{11}), 16);

    BOOST_CHECK(elements_1 == elements_2);
    BOOST_CHECK(elements_2 != elements_3);
}

BOOST_AUTO_TEST_CASE(test_serialize_round_trip)
{
    auto g = Point::GetBasePoint();
    Points gs(std::vector<Point> { g, g + g, g + g + g });

    DataStream ss{};
    gs.Serialize(ss);

    Points restored;
    restored.Unserialize(ss);
    BOOST_CHECK(restored == gs);

    // Scalars too
    Scalars xs(std::vector<Scalar> { Scalar{1}, Scalar{2}, Scalar{3} });
    DataStream ss2{};
    xs.Serialize(ss2);
    Scalars restored_xs;
    restored_xs.Unserialize(ss2);
    BOOST_CHECK(restored_xs == xs);
}

BOOST_AUTO_TEST_CASE(test_unserialize_rejects_oversized_length)
{
    // A length prefix that cannot possibly be satisfied by the remaining
    // bytes must be rejected before allocating, rather than eagerly sizing
    // the backing vector to a huge element count (memory-exhaustion DoS on
    // attacker-supplied tx/block data). Regression test for the
    // m_vec.resize(ReadCompactSize(s)) over-allocation.
    {
        DataStream ss{};
        // Claim 2^32 points but provide no element bytes.
        ::WriteCompactSize(ss, static_cast<uint64_t>(1) << 32);
        Points p;
        BOOST_CHECK_THROW(p.Unserialize(ss), std::ios_base::failure);
    }
    {
        DataStream ss{};
        ::WriteCompactSize(ss, static_cast<uint64_t>(1) << 32);
        Scalars xs;
        BOOST_CHECK_THROW(xs.Unserialize(ss), std::ios_base::failure);
    }
    {
        DataStream ss{};
        ::WriteCompactSize(ss, static_cast<uint64_t>(1) << 32);
        OrderedPoints op;
        BOOST_CHECK_THROW(op.Unserialize(ss), std::ios_base::failure);
    }
}

// Pins the canonical deterministic-shuffle order (seed handling through
// uint256_to_seed_array / compress_seed / XorShift32). The expected order is
// what LP64 little-endian nodes produce -- the consensus-canonical form after
// the explicit-LE read; a future endianness or width regression on any
// platform turns this red instead of silently forking the anonymity ring.
BOOST_AUTO_TEST_CASE(test_deterministic_shuffle_canonical_vector)
{
    OrderedElements<Point> set;
    for (int i = 1; i <= 8; ++i) {
        set.Add(Point::GetBasePoint() * Scalar(i));
    }
    uint256 seed;
    seed.SetHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    const auto shuffled = set.GetElements(seed, 8);
    BOOST_REQUIRE_EQUAL(shuffled.Size(), 8);

    // Scalar multiples of the base point serialize uniquely, so record which
    // multiple landed at each position.
    std::vector<int> got;
    for (size_t i = 0; i < shuffled.Size(); ++i) {
        for (int m = 1; m <= 8; ++m) {
            if (shuffled[i] == Point::GetBasePoint() * Scalar(m)) { got.push_back(m); break; }
        }
    }
    BOOST_REQUIRE_EQUAL(got.size(), 8U);
    const std::vector<int> expected{4, 6, 8, 7, 5, 3, 1, 2};
    BOOST_CHECK_EQUAL_COLLECTIONS(got.begin(), got.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_SUITE_END()
