// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_WORKER_POOL_H
#define BITCOIN_P2PMSG_WORKER_POOL_H

#include <sync.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <thread>
#include <vector>

class ArgsManager;

namespace p2pmsg {

using Task = std::function<void()>;

/**
 * Bounded task pool for p2p-message heavy crypto (Sphinx unwrap, BLS verify,
 * range proof checks). Net/consensus threads enqueue and return immediately;
 * dedicated workers execute. Drop-on-overflow — callers must not assume a
 * task will run once Enqueue returns false.
 */
class WorkerPool
{
public:
    struct Options {
        size_t num_workers{0};     // 0 = DefaultWorkerCount()
        size_t queue_capacity{0};  // 0 = DefaultQueueCapacity(num_workers)
    };

    WorkerPool();
    explicit WorkerPool(Options opts);
    explicit WorkerPool(const ArgsManager& args);
    ~WorkerPool();

    WorkerPool(const WorkerPool&) = delete;
    WorkerPool& operator=(const WorkerPool&) = delete;
    WorkerPool(WorkerPool&&) = delete;
    WorkerPool& operator=(WorkerPool&&) = delete;

    // Returns true if task was enqueued. Returns false and increments Dropped()
    // if queue is full or pool is stopping; task is destroyed.
    bool Enqueue(Task task) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    // Signal stop, wake workers, join. Tasks still in queue are discarded
    // (counted as dropped). Idempotent.
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t NumWorkers() const { return m_workers.size(); }
    size_t QueueCapacity() const { return m_capacity; }
    size_t QueueSize() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    uint64_t Submitted() const { return m_submitted.load(std::memory_order_relaxed); }
    uint64_t Completed() const { return m_completed.load(std::memory_order_relaxed); }
    uint64_t Dropped() const { return m_dropped.load(std::memory_order_relaxed); }

private:
    void Start(size_t num_workers);
    void WorkerLoop(size_t worker_idx) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t m_capacity;
    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<Task> m_queue GUARDED_BY(m_mutex);
    bool m_stopping GUARDED_BY(m_mutex){false};
    std::vector<std::thread> m_workers;

    std::atomic<uint64_t> m_submitted{0};
    std::atomic<uint64_t> m_completed{0};
    std::atomic<uint64_t> m_dropped{0};
};

// Default worker count = min(2, hardware_concurrency/4), clamped to [1, +inf).
size_t DefaultWorkerCount();

// Queue capacity = 2 * num_workers * 64 (at least 64).
size_t DefaultQueueCapacity(size_t num_workers);

// -onionworkers=N startup arg name.
extern const char* const ARG_ONION_WORKERS;

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_WORKER_POOL_H
