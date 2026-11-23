// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <univalue.h>
#include <wallet/privacy_score.h>

#include <bit>
#include <limits>

#include <boost/test/unit_test.hpp>

using namespace wallet;

BOOST_AUTO_TEST_SUITE(blsct_privacy_score_tests)

BOOST_AUTO_TEST_CASE(log2_milli_bits)
{
    BOOST_CHECK_EQUAL(Log2MilliBits(1), 0U);
    BOOST_CHECK_EQUAL(Log2MilliBits(2), 1000U);
    BOOST_CHECK_EQUAL(Log2MilliBits(3), 1584U);
    BOOST_CHECK_EQUAL(Log2MilliBits(4), 2000U);
    BOOST_CHECK_EQUAL(Log2MilliBits(5), 2321U);
    BOOST_CHECK_EQUAL(Log2MilliBits(7), 2807U);
    BOOST_CHECK_EQUAL(Log2MilliBits(8), 3000U);
    BOOST_CHECK_EQUAL(Log2MilliBits(1000), 9965U);
    BOOST_CHECK_EQUAL(Log2MilliBits(uint64_t{1} << 40), 40000U);
    BOOST_CHECK_EQUAL(Log2MilliBits((uint64_t{1} << 40) + 1), 40000U);
    BOOST_CHECK_EQUAL(Log2MilliBits((uint64_t{1} << 41) - 1), 40999U);
    BOOST_CHECK_EQUAL(Log2MilliBits(std::numeric_limits<uint64_t>::max()), 63999U);
    // Monotonic, and within one bit of the power of two below.
    PrivacyMilliBits prev{0};
    for (uint64_t n = 1; n < 5000; ++n) {
        const PrivacyMilliBits v{Log2MilliBits(n)};
        BOOST_CHECK(v >= prev);
        BOOST_CHECK_EQUAL(v / 1000, static_cast<PrivacyMilliBits>(std::bit_width(n) - 1));
        prev = v;
    }
}

BOOST_AUTO_TEST_CASE(compute_privacy_milli_bits)
{
    // Spending none of our coins: a receive, whatever the foreign inputs.
    BOOST_CHECK(ComputePrivacyMilliBits(0, {}) == PrivacyMilliBits{0});
    BOOST_CHECK(ComputePrivacyMilliBits(5, {}) == PrivacyMilliBits{0});
    // Our own send: the lowest of the coins spent.
    BOOST_CHECK(ComputePrivacyMilliBits(0, {3000, 1000, 2000}) == PrivacyMilliBits{1000});
    // Mixed with foreign inputs: log2(foreign + 1) on top of that.
    BOOST_CHECK(ComputePrivacyMilliBits(1, {0}) == PrivacyMilliBits{1000});
    BOOST_CHECK(ComputePrivacyMilliBits(3, {1000, 4000}) == PrivacyMilliBits{3000});
    BOOST_CHECK(ComputePrivacyMilliBits(2, {1000}) == PrivacyMilliBits{2584});
    // One unknown own input makes the result unknown.
    BOOST_CHECK(ComputePrivacyMilliBits(0, {1000, std::nullopt}) == std::nullopt);
    BOOST_CHECK(ComputePrivacyMilliBits(7, {std::nullopt}) == std::nullopt);
    // Saturates below the unknown encoding.
    BOOST_CHECK(ComputePrivacyMilliBits(1, {PRIVACY_MILLI_BITS_MAX}) == PRIVACY_MILLI_BITS_MAX);
    BOOST_CHECK(ComputePrivacyMilliBits(1, {PRIVACY_MILLI_BITS_MAX - 10}) == PRIVACY_MILLI_BITS_MAX);
    BOOST_CHECK(ComputePrivacyMilliBits(std::numeric_limits<uint64_t>::max(), {0}) == PrivacyMilliBits{63999});
}

BOOST_AUTO_TEST_CASE(privacy_bits_univalue)
{
    BOOST_CHECK(PrivacyBitsToUniValue(std::nullopt).isNull());
    BOOST_CHECK_EQUAL(PrivacyBitsToUniValue(PrivacyMilliBits{0}).write(), "0.000");
    BOOST_CHECK_EQUAL(PrivacyBitsToUniValue(PrivacyMilliBits{1584}).write(), "1.584");
    BOOST_CHECK_EQUAL(PrivacyBitsToUniValue(PrivacyMilliBits{12005}).write(), "12.005");
    BOOST_CHECK_EQUAL(PrivacyBitsToUniValue(PrivacyMilliBits{1584}).get_real(), 1.584);
}

BOOST_AUTO_TEST_SUITE_END()
