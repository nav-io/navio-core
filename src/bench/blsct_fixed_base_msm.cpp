// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Prototype benchmark: fixed-base precompute for the range-proof verification MSM.
//
// Bulletproofs+ verification (and, identically, the PoS set-membership proof)
// collapses each proof into one multi-scalar multiplication that mixes:
//   - per-proof VARIABLE points (A, A_wip, B, Ls, Rs, Vs / the staked-commitment
//     set Ys), different every proof;
//   - a set of FIXED generators (Gi/Hi for range proofs, setup.hs for set
//     membership) that are identical across every proof on the chain.
//
// The production path (mclBnG1_mulVecMT) rebuilds its per-point NAF tables on
// every call, re-deriving the fixed generators' tables millions of times over a
// sync. FixedBaseWindow builds each fixed generator's window table once and
// reuses it — the classic fixed-base window method.
//
// This bench isolates the fixed-base half of the MSM (mn generator points) and,
// over R proofs sharing those generators, compares:
//   MulVecMT  - the production path, one mclBnG1_mulVecMT(mn) per proof.
//   Naive     - per-point base*scalar + add through the C-API (fair per-op floor).
//   Window<w> - FixedBaseWindow (the shared helper also used in verification),
//               tables built once then reused each round.
//
// The window result is checked bit-identical to the production MSM at fixture
// construction (consensus determinism) -- a mismatch throws and fails the
// bench run -- and each table's footprint is logged.
//
// FixedBaseWindow is built on navio's MclG1Point wrapper (routing through the
// initialised C ABI), so every point op pays a C-API call. mcl's header-only
// WindowMethod<G1> is unusable here: it would instantiate a second, uninitialised
// copy of mcl's static curve state in this TU. The wrapper's per-op tax means a
// win here is a lower bound on a properly inlined version.

#include <bench/bench.h>

#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_init.h>
#include <blsct/building_block/fixed_base_window.h>

#include <tinyformat.h>

#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

using Point = MclG1Point;
using Scalar = MclScalar;

struct FixedBaseFixture {
    size_t n; // number of fixed generator points (== mn of the proof)
    size_t R; // number of proofs reusing those generators

    std::vector<Point> bases;
    std::vector<std::vector<Scalar>> exps;
    // Flattened underlyings for the mulVecMT path.
    std::vector<Point::Underlying> base_u;
    std::vector<std::vector<Scalar::Underlying>> exp_u;

    FixedBaseFixture(size_t n_, size_t R_) : n(n_), R(R_)
    {
        volatile MclInit mcl_init;
        (void)mcl_init;

        bases.reserve(n);
        base_u.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            bases.emplace_back(Point::Rand());
            base_u.push_back(bases.back().GetUnderlying());
        }
        exps.resize(R);
        exp_u.resize(R);
        for (size_t r = 0; r < R; ++r) {
            exps[r].reserve(n);
            exp_u[r].reserve(n);
            for (size_t i = 0; i < n; ++i) {
                exps[r].emplace_back(Scalar::Rand(true));
                exp_u[r].push_back(exps[r].back().GetUnderlying());
            }
        }
    }

    Point MulVecMT(size_t r) const
    {
        Point::Underlying pv;
        mclBnG1_mulVecMT(&pv, const_cast<Point::Underlying*>(base_u.data()),
                         const_cast<Scalar::Underlying*>(exp_u[r].data()), n, 0);
        return Point(pv);
    }

    Point Naive(size_t r) const
    {
        Point acc;
        for (size_t i = 0; i < n; ++i) acc = acc + bases[i] * exps[r][i];
        return acc;
    }
};

void RunMulVecMT(benchmark::Bench& bench, size_t n, size_t R)
{
    FixedBaseFixture fx(n, R);
    bench.batch(R).unit("proof").run([&] {
        for (size_t r = 0; r < R; ++r) {
            Point p = fx.MulVecMT(r);
            ankerl::nanobench::doNotOptimizeAway(p);
        }
    });
}

void RunNaive(benchmark::Bench& bench, size_t n, size_t R)
{
    FixedBaseFixture fx(n, R);
    bench.batch(R).unit("proof").run([&] {
        for (size_t r = 0; r < R; ++r) {
            Point p = fx.Naive(r);
            ankerl::nanobench::doNotOptimizeAway(p);
        }
    });
}

void RunWindow(benchmark::Bench& bench, size_t n, size_t R, size_t winSize)
{
    FixedBaseFixture fx(n, R);
    FixedBaseWindow fbw(fx.bases, winSize);

    // Consensus determinism: window MSM must equal the production MSM exactly.
    // Throwing makes the bench run fail; a stderr note would leave exit status
    // 0 and go unnoticed.
    if (!(fbw.MSM(fx.exps[0], n) == fx.MulVecMT(0))) {
        throw std::runtime_error(strprintf("FixedBaseWindow MISMATCH (n=%d w=%d)", n, winSize));
    }
    std::cerr << "  [window w=" << winSize << " n=" << n << "] ~"
              << (fbw.Bytes() >> 20) << " MiB tables\n";

    bench.batch(R).unit("proof").run([&] {
        for (size_t r = 0; r < R; ++r) {
            Point p = fbw.MSM(fx.exps[r], n);
            ankerl::nanobench::doNotOptimizeAway(p);
        }
    });
}

constexpr size_t kRounds = 16; // proofs reusing the same generators

} // namespace

// mn = 64  → a single non-aggregated 64-bit range proof.
static void BLSCTFixedBaseMulVecMT_64(benchmark::Bench& b) { RunMulVecMT(b, 64, kRounds); }
static void BLSCTFixedBaseNaive_64(benchmark::Bench& b)    { RunNaive(b, 64, kRounds); }
static void BLSCTFixedBaseWindow4_64(benchmark::Bench& b)  { RunWindow(b, 64, kRounds, 4); }
static void BLSCTFixedBaseWindow8_64(benchmark::Bench& b)  { RunWindow(b, 64, kRounds, 8); }

// mn = 256 → an aggregated proof (e.g. 4 outputs) / a mid-size membership set.
static void BLSCTFixedBaseMulVecMT_256(benchmark::Bench& b) { RunMulVecMT(b, 256, kRounds); }
static void BLSCTFixedBaseNaive_256(benchmark::Bench& b)    { RunNaive(b, 256, kRounds); }
static void BLSCTFixedBaseWindow4_256(benchmark::Bench& b)  { RunWindow(b, 256, kRounds, 4); }
static void BLSCTFixedBaseWindow8_256(benchmark::Bench& b)  { RunWindow(b, 256, kRounds, 8); }

BENCHMARK(BLSCTFixedBaseMulVecMT_64,  benchmark::PriorityLevel::LOW);
BENCHMARK(BLSCTFixedBaseNaive_64,     benchmark::PriorityLevel::LOW);
BENCHMARK(BLSCTFixedBaseWindow4_64,   benchmark::PriorityLevel::LOW);
BENCHMARK(BLSCTFixedBaseWindow8_64,   benchmark::PriorityLevel::LOW);
BENCHMARK(BLSCTFixedBaseMulVecMT_256, benchmark::PriorityLevel::LOW);
BENCHMARK(BLSCTFixedBaseNaive_256,    benchmark::PriorityLevel::LOW);
BENCHMARK(BLSCTFixedBaseWindow4_256,  benchmark::PriorityLevel::LOW);
BENCHMARK(BLSCTFixedBaseWindow8_256,  benchmark::PriorityLevel::LOW);
