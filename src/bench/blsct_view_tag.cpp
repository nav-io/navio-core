// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_init.h>
#include <blsct/wallet/helpers.h>

#include <vector>

using blsct::CalculateViewTag;
using blsct::CalculateViewTagBatch;

namespace {

struct ViewTagFixture {
    std::vector<MclG1Point> blindingKeys;
    MclScalar viewKey;

    explicit ViewTagFixture(size_t n)
    {
        volatile MclInit mcl_init;
        (void)mcl_init;
        viewKey = MclScalar::Rand(true);
        blindingKeys.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            MclScalar r = MclScalar::Rand(true);
            blindingKeys.emplace_back(MclG1Point::GetBasePoint() * r);
        }
    }
};

// Per-output serial loop — the shape of the current hot path (pre-batch).
static void ViewTagSerial(benchmark::Bench& bench, size_t n)
{
    ViewTagFixture fx(n);
    bench.batch(n).unit("view-tag").run([&] {
        for (size_t i = 0; i < n; ++i) {
            uint64_t tag = CalculateViewTag(fx.blindingKeys[i], fx.viewKey);
            ankerl::nanobench::doNotOptimizeAway(tag);
        }
    });
}

// Batched multi-threaded path — the new CalculateViewTagBatch.
static void ViewTagBatch(benchmark::Bench& bench, size_t n)
{
    ViewTagFixture fx(n);
    bench.batch(n).unit("view-tag").run([&] {
        auto tags = CalculateViewTagBatch(fx.blindingKeys, fx.viewKey);
        ankerl::nanobench::doNotOptimizeAway(tags.data());
    });
}

} // namespace

static void BLSCTViewTagSerial_1(benchmark::Bench& b)    { ViewTagSerial(b, 1); }
static void BLSCTViewTagSerial_16(benchmark::Bench& b)   { ViewTagSerial(b, 16); }
static void BLSCTViewTagSerial_256(benchmark::Bench& b)  { ViewTagSerial(b, 256); }
static void BLSCTViewTagSerial_4096(benchmark::Bench& b) { ViewTagSerial(b, 4096); }

static void BLSCTViewTagBatch_1(benchmark::Bench& b)    { ViewTagBatch(b, 1); }
static void BLSCTViewTagBatch_16(benchmark::Bench& b)   { ViewTagBatch(b, 16); }
static void BLSCTViewTagBatch_256(benchmark::Bench& b)  { ViewTagBatch(b, 256); }
static void BLSCTViewTagBatch_4096(benchmark::Bench& b) { ViewTagBatch(b, 4096); }

BENCHMARK(BLSCTViewTagSerial_1,    benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTViewTagSerial_16,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTViewTagSerial_256,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTViewTagSerial_4096, benchmark::PriorityLevel::HIGH);

BENCHMARK(BLSCTViewTagBatch_1,    benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTViewTagBatch_16,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTViewTagBatch_256,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTViewTagBatch_4096, benchmark::PriorityLevel::HIGH);
