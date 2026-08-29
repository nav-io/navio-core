// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BUILDING_BLOCK_FIXED_BASE_WINDOW_H
#define NAVIO_BLSCT_BUILDING_BLOCK_FIXED_BASE_WINDOW_H

#include <blsct/arith/blst/blst_g1point.h>
#include <blsct/arith/blst/blst_scalar.h>

#include <blst.h>

#include <cstdint>
#include <vector>

// Fixed-base multi-scalar multiplication for a set of points that never change
// (the Bulletproofs+ range-proof generators Gi/Hi/H). The window table is built
// ONCE, at construction, with blst native precompute (blst_p1s_mult_wbits_
// precompute); a later MSM over those bases is a single blst_p1s_mult_wbits
// call using that table, instead of the bucket tables blst mulVec rebuilds on
// every call.
//
// The result of MSM() is bit-identical to BlstUtil::MSM over the same bases and
// scalars (elliptic-curve addition is associative/commutative), so this is safe
// inside consensus verification: only the final point matters.
//
// Table footprint is npoints * 2^(winSize-1) affine points, so memory grows
// with winSize -- meant to cover a bounded PREFIX of the generator pool under a
// memory budget, with the caller falling back to the generic MSM for scalar
// counts beyond size().
class FixedBaseWindow
{
public:
    FixedBaseWindow() = default;
    FixedBaseWindow(const std::vector<BlstG1Point>& bases, size_t winSize);

    size_t size() const { return m_nbases; }
    size_t winSize() const { return m_wbits; }
    bool empty() const { return m_nbases == 0; }
    // Total precompute-table footprint in bytes.
    size_t Bytes() const { return m_table.size() * sizeof(blst_p1_affine); }

    // Returns the sum over i<count of base_i * exps[i]. `count` is clamped to
    // size(): a count beyond the tabled bases would index out of bounds, so the
    // clamp is enforced here rather than documented at the caller. Accepts any
    // scalar container exposing operator[] -> BlstScalar (Elements<BlstScalar>,
    // std::vector<BlstScalar>); it copies the first `count` into a contiguous
    // buffer and defers to the blst implementation.
    template <typename ScalarVec>
    BlstG1Point MSM(const ScalarVec& exps, size_t count) const
    {
        if (count > m_nbases) count = m_nbases;
        std::vector<BlstScalar> sc;
        sc.reserve(count);
        for (size_t i = 0; i < count; ++i) sc.push_back(exps[i]);
        return MSMImpl(sc.data(), count);
    }

private:
    BlstG1Point MSMImpl(const BlstScalar* exps, size_t count) const;

    size_t m_wbits = 0;
    size_t m_nbases = 0;
    // blst wbits precompute table for all m_nbases bases; row i is at a fixed
    // per-point offset, so a query with count < m_nbases reads the first count
    // rows and is valid.
    std::vector<blst_p1_affine> m_table;
};

#endif // NAVIO_BLSCT_BUILDING_BLOCK_FIXED_BASE_WINDOW_H
