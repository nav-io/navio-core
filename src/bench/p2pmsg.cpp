// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <p2pmsg/worker_pool.h>

#include <atomic>
#include <chrono>
#include <thread>

using namespace p2pmsg;

// Note on PoW tuning (no bench here): a PoW attempt is one SHA256 over the
// ~98-byte header. At ~15 ns/attempt (~65M attempts/s on a modern core) a
// `bits`-bit target costs ~2^bits / 65e6 seconds honest. So 22 bits ≈ 65 ms and
// 23 bits ≈ 130 ms on a fast core, more on slow ones. DEFAULT_POW_BITS = 23
// targets ~100-200 ms honest. (Can't bench it in this harness: PoWHeader::Hash
// serializes a BLS G1 pubkey and mcl is not initialised in bench_navio.)

// Throughput of submit + execute for trivial jobs through the bounded ring.
// Measures the enqueue/dispatch overhead, not the (absent) crypto payload.
static void WorkerPoolThroughput(benchmark::Bench& bench)
{
    std::atomic<uint64_t> done{0};

    WorkerPool pool{WorkerPool::Options{/*num_workers=*/2, /*ring_capacity=*/1024}};
    pool.RegisterHandler(1, [&](const Job&) {
        done.fetch_add(1, std::memory_order_relaxed);
    });
    pool.Start();

    Job job;
    job.kind = 1;
    job.len = 0;

    bench.unit("job").run([&] {
        while (!pool.Enqueue(job)) {
            std::this_thread::yield();
        }
    });

    // Let in-flight jobs drain before the pool is torn down.
    pool.Stop();
}
BENCHMARK(WorkerPoolThroughput, benchmark::PriorityLevel::HIGH);
