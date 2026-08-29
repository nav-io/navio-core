// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/blst/blst_util.h>

#include <algorithm>
#include <thread>

namespace {

std::atomic<size_t> g_blst_default_threads{1};

// Same heuristic as blst's internal pippenger_window_size() (multi_scalar.c).
size_t PippengerWindowSize(size_t npoints)
{
    size_t wbits = 0;
    for (; npoints >>= 1; wbits++) {}
    if (wbits > 12) return wbits - 3;
    if (wbits > 8) return wbits - 2;
    if (wbits > 4) return wbits - 1;
    return wbits ? 2 : 1;
}

constexpr size_t kScalarBits = 255;

} // namespace

void BlstUtil::SetDefaultThreads(size_t threads)
{
    g_blst_default_threads.store(threads);
}

size_t BlstUtil::DefaultThreads()
{
    return g_blst_default_threads.load();
}

BlstG1Point BlstUtil::MSM(const BlstG1Point* pts, const BlstScalar* scalars, size_t n, size_t threads)
{
    if (n == 0) return BlstG1Point();
    if (threads == 0) threads = DefaultThreads();
    if (threads == 0) {
        threads = std::thread::hardware_concurrency();
        if (threads == 0) threads = 1;
    }

    // blst's MSM takes affine points and canonical little-endian scalars.
    // The Jacobian -> affine conversion is a batched inversion; mcl's mulVec
    // pays the equivalent internally, so it is part of the measured cost.
    static_assert(sizeof(BlstG1Point) == sizeof(blst_p1));
    std::vector<blst_p1_affine> aff(n);
    {
        const blst_p1* in[2] = {&pts[0].m_point, nullptr};
        blst_p1s_to_affine(aff.data(), in, n);
    }
    std::vector<blst_scalar> sc(n);
    for (size_t i = 0; i < n; ++i) {
        blst_scalar_from_fr(&sc[i], &scalars[i].m_scalar);
    }
    const blst_p1_affine* ap[2] = {aff.data(), nullptr};
    const byte* sp[2] = {sc[0].b, nullptr};

    if (threads <= 1 || n < 32) {
        std::vector<limb_t> scratch(blst_p1s_mult_pippenger_scratch_sizeof(n) / sizeof(limb_t) + 1);
        BlstG1Point ret;
        blst_p1s_mult_pippenger(&ret.m_point, ap, n, sp, kScalarBits, scratch.data());
        return ret;
    }

    // Window tiling across threads. Each tile k covers scalar bits
    // [k*window, min((k+1)*window, 255)); the fold walks tiles from the top,
    // doubling `window` times between rows.
    //
    // blst's tiles use signed-digit (Booth) recoding: every window also
    // consumes the carry out of the window below it, so the topmost tile must
    // be a *partial* one (bit0 + window > nbits gives it wbits+1 bucket bits
    // for that carry). Hence ny = nbits / window + 1 — when window divides
    // nbits the top tile has width 0 and holds just the carry — exactly as
    // blst's own mult_pippenger loop and its Rust bindings lay it out.
    const size_t window = PippengerWindowSize(n);
    const size_t ny = kScalarBits / window + 1;
    threads = std::min(threads, ny);
    std::vector<blst_p1> tiles(ny);
    std::atomic<size_t> next{0};
    const size_t scratch_limbs = (blst_p1s_mult_pippenger_scratch_sizeof(0) << (window - 1)) / sizeof(limb_t) + 1;

    auto worker = [&]() {
        std::vector<limb_t> scratch(scratch_limbs);
        for (;;) {
            const size_t k = next.fetch_add(1, std::memory_order_relaxed);
            if (k >= ny) return;
            const size_t bit0 = k * window;
            blst_p1s_tile_pippenger(&tiles[k], ap, n, sp, kScalarBits, scratch.data(), bit0, window);
        }
    };
    std::vector<std::thread> pool;
    pool.reserve(threads - 1);
    for (size_t t = 1; t < threads; ++t) pool.emplace_back(worker);
    worker();
    for (auto& th : pool) th.join();

    BlstG1Point ret;
    for (size_t k = ny; k-- > 0;) {
        blst_p1_add_or_double(&ret.m_point, &ret.m_point, &tiles[k]);
        if (k > 0) {
            for (size_t i = 0; i < window; ++i) blst_p1_double(&ret.m_point, &ret.m_point);
        }
    }
    return ret;
}
