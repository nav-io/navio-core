// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/elements.h>
#include <blsct/arith/blst/blst.h>
#include <blsct/building_block/fixed_base_window.h>
#include <blsct/building_block/lazy_points.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

// The fixed-base window MSM is used to accelerate range-proof verification. Its
// result MUST be bit-identical to the production LazyPoints::Sum (BlstUtil::MSM)
// over the same bases and scalars, because only the summed point crosses the
// consensus boundary. These tests pin that equivalence across window sizes,
// scalar edge cases, and partial (count < size) evaluations.

BOOST_FIXTURE_TEST_SUITE(fixed_base_window_tests, BasicTestingSetup)

namespace {

// Reference MSM via the exact production path used inside VerifyProofs.
BlstG1Point ReferenceMSM(const std::vector<BlstG1Point>& bases,
                        const std::vector<BlstScalar>& exps,
                        size_t count)
{
    LazyPoints<Blst> lp;
    for (size_t i = 0; i < count; ++i) lp.Add(bases[i], exps[i]);
    return lp.Sum();
}

std::vector<BlstG1Point> RandBases(size_t n)
{
    std::vector<BlstG1Point> v;
    v.reserve(n);
    for (size_t i = 0; i < n; ++i) v.push_back(BlstG1Point::Rand());
    return v;
}

} // namespace

BOOST_AUTO_TEST_CASE(matches_reference_across_window_sizes)
{
    const size_t n = 96;
    auto bases = RandBases(n);
    std::vector<BlstScalar> exps;
    for (size_t i = 0; i < n; ++i) exps.push_back(BlstScalar::Rand(true));

    for (size_t w : {2, 4, 5, 8, 11}) {  // blst wbits requires width >= 2
        FixedBaseWindow fbw(bases, w);
        BOOST_CHECK_EQUAL(fbw.size(), n);
        BlstG1Point got = fbw.MSM(exps, n);
        BlstG1Point ref = ReferenceMSM(bases, exps, n);
        BOOST_CHECK_MESSAGE(got == ref, "window MSM mismatch at winSize=" << w);
    }
}

BOOST_AUTO_TEST_CASE(matches_reference_partial_count)
{
    const size_t n = 128;
    auto bases = RandBases(n);
    std::vector<BlstScalar> exps;
    for (size_t i = 0; i < n; ++i) exps.push_back(BlstScalar::Rand(true));

    FixedBaseWindow fbw(bases, 8);
    for (size_t count : {size_t{0}, size_t{1}, size_t{63}, size_t{64}, size_t{127}, n}) {
        BlstG1Point got = fbw.MSM(exps, count);
        BlstG1Point ref = ReferenceMSM(bases, exps, count);
        BOOST_CHECK_MESSAGE(got == ref, "window MSM mismatch at count=" << count);
    }
}

BOOST_AUTO_TEST_CASE(handles_scalar_edge_values)
{
    std::vector<BlstG1Point> bases = RandBases(4);
    // 0, 1, and a large value near the field order exercise the top window.
    std::vector<BlstScalar> exps = {
        BlstScalar(0),
        BlstScalar(1),
        BlstScalar(0) - BlstScalar(1), // r - 1, the maximum reduced scalar
        BlstScalar(255),
    };
    FixedBaseWindow fbw(bases, 8);
    BlstG1Point got = fbw.MSM(exps, bases.size());
    BlstG1Point ref = ReferenceMSM(bases, exps, bases.size());
    BOOST_CHECK(got == ref);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_window_size)
{
    // Validation must happen before any member computes with the value:
    // winSize 0 would divide by zero in an initializer, large values would
    // shift out of range. Both must throw, not reach UB.
    std::vector<BlstG1Point> bases = RandBases(1);
    BOOST_CHECK_THROW(FixedBaseWindow(bases, 0), std::invalid_argument);
    // blst wbits requires a window width >= 2; width 1 aborts inside blst.
    BOOST_CHECK_THROW(FixedBaseWindow(bases, 1), std::invalid_argument);
    BOOST_CHECK_THROW(FixedBaseWindow(bases, 17), std::invalid_argument);
    BOOST_CHECK_THROW(FixedBaseWindow(bases, 64), std::invalid_argument);
    BOOST_CHECK_NO_THROW(FixedBaseWindow(bases, 16));
}

BOOST_AUTO_TEST_SUITE_END()
