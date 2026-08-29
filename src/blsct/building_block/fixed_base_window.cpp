// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/building_block/fixed_base_window.h>

#include <stdexcept>

namespace {
// blst scalars are read at nbits = 255 (Fr is < 255 bits), matching
// BlstUtil::MSM so the fixed-base result is bit-identical to the generic path.
constexpr size_t kScalarBits = 255;

// Validated before any member computes with it: winSize is the blst window
// width (wbits). Values outside blst's supported range would size the table
// nonsensically; a consensus building block must not rely on its caller for
// well-definedness. blst supports small window widths; the cache clamps its
// input to 1..12.
size_t CheckedWinSize(size_t winSize)
{
    if (winSize < 2 || winSize > 16) {
        throw std::invalid_argument("FixedBaseWindow: winSize must be in [2, 16]");
    }
    return winSize;
}
} // namespace

FixedBaseWindow::FixedBaseWindow(const std::vector<BlstG1Point>& bases, size_t winSize)
    : m_wbits(CheckedWinSize(winSize)),
      m_nbases(bases.size())
{
    if (m_nbases == 0) return;

    // Jacobian -> affine once for the whole base set (contiguous-array
    // convention: the {ptr, nullptr} pair tells blst points[0] is a contiguous
    // array of m_nbases elements).
    static_assert(sizeof(BlstG1Point) == sizeof(blst_p1));
    std::vector<blst_p1_affine> aff(m_nbases);
    const blst_p1* in[2] = {&bases[0].m_point, nullptr};
    blst_p1s_to_affine(aff.data(), in, m_nbases);

    const blst_p1_affine* ap[2] = {aff.data(), nullptr};
    const size_t bytes = blst_p1s_mult_wbits_precompute_sizeof(m_wbits, m_nbases);
    m_table.resize(bytes / sizeof(blst_p1_affine) + 1);
    blst_p1s_mult_wbits_precompute(m_table.data(), m_wbits, ap, m_nbases);
}

BlstG1Point FixedBaseWindow::MSMImpl(const BlstScalar* exps, size_t count) const
{
    if (count == 0 || m_nbases == 0) return BlstG1Point();
    if (count > m_nbases) count = m_nbases;

    std::vector<blst_scalar> sc(count);
    for (size_t i = 0; i < count; ++i) {
        blst_scalar_from_fr(&sc[i], &exps[i].m_scalar);
    }
    const byte* sp[2] = {sc[0].b, nullptr};

    std::vector<limb_t> scratch(blst_p1s_mult_wbits_scratch_sizeof(count) / sizeof(limb_t) + 1);
    BlstG1Point ret;
    // count may be < m_nbases: blst lays the precompute table out row-major
    // per point (npoints rows of 2^(wbits-1) affine entries, row stride
    // independent of the total npoints -- see blst multi_scalar.c), so a query
    // with fewer points reads the first `count` rows and is valid. The
    // count < size() path is covered by the bit-identity unit test.
    blst_p1s_mult_wbits(&ret.m_point, m_table.data(), m_wbits, count, sp, kScalarBits, scratch.data());
    return ret;
}
