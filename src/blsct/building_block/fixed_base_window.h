// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BUILDING_BLOCK_FIXED_BASE_WINDOW_H
#define NAVIO_BLSCT_BUILDING_BLOCK_FIXED_BASE_WINDOW_H

#include <blsct/arith/mcl/mcl_g1point.h>
#include <blsct/arith/mcl/mcl_scalar.h>

#include <cstdint>
#include <vector>

// Fixed-base window method for a set of points that never change (the
// Bulletproofs+ range-proof generators Gi/Hi/H). Each base gets a precomputed
// window table built ONCE; a later multi-scalar multiplication over those bases
// is then a table-lookup + add per base, instead of the NAF tables mcl's
// mulVec rebuilds on every call.
//
// The result of MSM() is bit-identical to mclBnG1_mulVecMT over the same bases
// and scalars (elliptic-curve addition is associative/commutative), so this is
// safe to use inside consensus verification: only the final point matters.
//
// Table footprint per base is (256/winSize) * 2^winSize points, so memory grows
// fast with winSize — this is meant to cover a bounded PREFIX of the generator
// pool under a memory budget, with the caller falling back to the generic MSM
// for scalar counts beyond size().
class FixedBaseWindow
{
public:
    FixedBaseWindow() = default;
    FixedBaseWindow(const std::vector<MclG1Point>& bases, size_t winSize);

    size_t size() const { return m_nbases; }
    size_t winSize() const { return m_winSize; }
    bool empty() const { return m_nbases == 0; }
    // Total table footprint in bytes.
    size_t Bytes() const { return m_tbl.size() * sizeof(MclG1Point::Underlying); }

    // Returns Σ_{i<count} base_i * exps[i], where count = min(exps.size(), size()).
    // The caller must ensure exps.size() <= size() for a full result; the method
    // asserts this in debug builds.
    template <typename ScalarVec>
    MclG1Point MSM(const ScalarVec& exps, size_t count) const
    {
        MclG1Point acc; // identity
        for (size_t i = 0; i < count; ++i) {
            acc = acc + MulOne(i, exps[i]);
        }
        return acc;
    }

private:
    // Windowed multiply of base i by scalar s, using its precomputed table.
    MclG1Point MulOne(size_t i, const MclScalar& s) const;

    static constexpr size_t kBitSize = 256; // Fr is < 255 bits; round to a byte.

    size_t m_winSize = 0;
    size_t m_tblNum = 0;
    size_t m_r = 0; // 1 << winSize
    size_t m_nbases = 0;
    // Flattened tables: base i occupies [i*m_tblNum*m_r, (i+1)*m_tblNum*m_r).
    // Entry (block b, digit v) is at i*m_tblNum*m_r + b*m_r + v == v * 2^(b*w) * base_i.
    std::vector<MclG1Point> m_tbl;
};

#endif // NAVIO_BLSCT_BUILDING_BLOCK_FIXED_BASE_WINDOW_H
