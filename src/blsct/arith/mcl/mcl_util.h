// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_ARITH_MCL_MCL_UTIL_H
#define NAVIO_BLSCT_ARITH_MCL_MCL_UTIL_H

#define BLS_ETH 1

#include <bls/bls384_256.h>
#include <blsct/arith/mcl/mcl_g1point.h>
#include <blsct/arith/mcl/mcl_scalar.h>
#include <blsct/building_block/lazy_point.h>

struct MclUtil {
    // using template to avoid circular dependency problem with Mcl class
    template <typename T>
    static MclG1Point MultiplyLazyPoints(const std::vector<LazyPoint<T>>& points)
    {
        std::vector<MclG1Point::Underlying> bases;
        std::vector<MclScalar::Underlying> exps;

        bases.reserve(points.size());
        exps.reserve(points.size());
        for (const auto& point: points) {
            bases.push_back(point.m_base.GetUnderlying());
            exps.push_back(point.m_exp.GetUnderlying());
        }
        MclG1Point::Underlying pv;
        // Use the multi-threaded MSM. With cpuN = 0, MCL auto-detects the
        // number of cores and internally falls back to single-threaded
        // execution when n is small enough that threading would not help
        // (see mcl/ec.hpp: mulVecMT). When MCL is built without
        // MCL_USE_OMP, this symbol degrades to a plain mulVec call
        // (see mcl/ec.hpp:1719-1722), so the call is always safe.
        // The result is bit-identical regardless of cpuN because EC point
        // addition is commutative and associative, which preserves
        // consensus determinism.
        mclBnG1_mulVecMT(&pv, bases.data(), exps.data(), points.size(), 0);
        return MclG1Point(pv);
    }
};

#endif // NAVIO_BLSCT_ARITH_MCL_MCL_UTIL_H
