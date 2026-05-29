// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <p2pmsg/worker_pool.h>

#include <atomic>
#include <chrono>
#include <thread>

using namespace p2pmsg;

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
