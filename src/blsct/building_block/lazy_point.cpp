// Copyright (c) 2022 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl.h>
#include <blsct/building_block/lazy_point.h>

template <typename T>
LazyPoint<T>::LazyPoint(
    const typename T::Point& base,
    const typename T::Scalar& exp
): m_base(base.m_point), m_exp(exp.m_scalar)
{
}
template LazyPoint<Mcl>::LazyPoint(
    const Mcl::Point& base,
    const Mcl::Scalar& exp
);

// ---------------------------------------------------------------------------
// Optional supranational/blst arith backend (cmake -DWITH_BLST=ON). Mirrors
// the Mcl instantiations above 1:1; compiled out of default builds.
#ifdef NAVIO_BLSCT_ARITH_BLST
#include <blsct/arith/blst/blst.h>
template LazyPoint<Blst>::LazyPoint(
    const Blst::Point& base,
    const Blst::Scalar& exp
);
#endif // NAVIO_BLSCT_ARITH_BLST
