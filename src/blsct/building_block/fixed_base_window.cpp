// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/building_block/fixed_base_window.h>

namespace {
// 32-byte little-endian form of a scalar, for window-digit extraction.
std::vector<uint8_t> ScalarLE(const MclScalar& s)
{
    std::vector<uint8_t> be = s.GetVch(); // untrimmed 32-byte big-endian form
    std::vector<uint8_t> le(be.rbegin(), be.rend());
    le.resize(32, 0);
    return le;
}

// Extract the winSize-bit window starting at bit `bit` (LSB-first).
inline uint32_t Window(const std::vector<uint8_t>& le, size_t bit, size_t winSize, size_t bitSize)
{
    uint32_t v = 0;
    for (size_t k = 0; k < winSize; ++k) {
        size_t b = bit + k;
        if (b >= bitSize) break;
        uint32_t one = (le[b >> 3] >> (b & 7)) & 1u;
        v |= one << k;
    }
    return v;
}
} // namespace

FixedBaseWindow::FixedBaseWindow(const std::vector<MclG1Point>& bases, size_t winSize)
    : m_winSize(winSize),
      m_tblNum((kBitSize + winSize - 1) / winSize),
      m_r(size_t(1) << winSize),
      m_nbases(bases.size())
{
    m_tbl.assign(m_nbases * m_tblNum * m_r, MclG1Point()); // MclG1Point() is identity
    for (size_t i = 0; i < m_nbases; ++i) {
        MclG1Point t = bases[i];
        MclG1Point* base_tbl = &m_tbl[i * m_tblNum * m_r];
        for (size_t b = 0; b < m_tblNum; ++b) {
            MclG1Point* w = &base_tbl[b * m_r];
            // w[0] stays identity; build w[j] = j * t via doubling spans, then t *= 2^winSize.
            for (size_t d = 1; d < m_r; d *= 2) {
                for (size_t j = 0; j < d; ++j) {
                    w[j + d] = w[j] + t;
                }
                t = t.Double();
            }
        }
    }
}

MclG1Point FixedBaseWindow::MulOne(size_t i, const MclScalar& s) const
{
    const std::vector<uint8_t> le = ScalarLE(s);
    const MclG1Point* base_tbl = &m_tbl[i * m_tblNum * m_r];
    MclG1Point z; // identity
    for (size_t b = 0; b < m_tblNum; ++b) {
        uint32_t v = Window(le, b * m_winSize, m_winSize, kBitSize);
        if (v) z = z + base_tbl[b * m_r + v];
    }
    return z;
}
