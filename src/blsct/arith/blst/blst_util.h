// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_ARITH_BLST_BLST_UTIL_H
#define NAVIO_BLSCT_ARITH_BLST_BLST_UTIL_H

#include <blsct/arith/blst/blst_g1point.h>
#include <blsct/arith/blst/blst_scalar.h>

#include <atomic>
#include <cstddef>
#include <vector>

// LazyPoint is forward-declared instead of included: lazy_point.cpp
// instantiates the <Blst> templates via blst.h, so including
// building_block/lazy_point.h here would close the include cycle
// blst -> blst_util -> lazy_point -> blst. MultiplyLazyPoints is a template,
// so its instantiation sites see the complete type.
template <typename T>
struct LazyPoint;

struct BlstUtil {
    // Multi-scalar multiplication Σ scalars[i] * pts[i] via blst's Pippenger.
    //
    // blst has no built-in threading. `threads` selects the strategy:
    //   1  -> single blst_p1s_mult_pippenger call.
    //   n  -> the 255-bit scalar range is cut into Pippenger windows and the
    //         per-window "tiles" (blst_p1s_tile_pippenger) are farmed out to n
    //         std::threads, then folded with window-sized doublings — the same
    //         scheme blst's own Rust bindings use for multi-threaded MSM.
    //   0  -> DefaultThreads() (see below).
    // The result is identical for every thread count (EC addition is
    // associative/commutative), which is what consensus needs.
    static BlstG1Point MSM(const BlstG1Point* pts, const BlstScalar* scalars, size_t n, size_t threads = 0);

    // Process-wide thread count used by MultiplyLazyPoints when `threads`
    // is 0: 1 == single-threaded (the default), 0 == hardware_concurrency().
    static void SetDefaultThreads(size_t threads);
    static size_t DefaultThreads();

    // using template to avoid circular dependency problem with Blst class
    template <typename T>
    static BlstG1Point MultiplyLazyPoints(const std::vector<LazyPoint<T>>& points)
    {
        std::vector<BlstG1Point> bases;
        std::vector<BlstScalar> exps;
        bases.reserve(points.size());
        exps.reserve(points.size());
        for (const auto& point : points) {
            bases.push_back(point.m_base);
            exps.push_back(point.m_exp);
        }
        return MSM(bases.data(), exps.data(), bases.size(), 0);
    }
};

#endif // NAVIO_BLSCT_ARITH_BLST_BLST_UTIL_H
