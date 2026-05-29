// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_WORKER_POOL_H
#define BITCOIN_P2PMSG_WORKER_POOL_H

#include <sync.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <thread>
#include <vector>

class ArgsManager;

namespace p2pmsg {

//! Maximum payload size carried inline in a Job. Sized to hold the largest
//! p2pmsg wire payload (ECIES-wrapped BLSCT half-tx). Net thread rejects
//! anything larger before enqueue, so workers never see oversized jobs.
static constexpr size_t MAX_JOB_BYTES = 4096;

//! Peer identifier. Mirrors net.h NodeId without pulling in the heavy header.
using PeerId = int64_t;

/**
 * A unit of heavy crypto work. POD by design: the net thread fills one of these
 * and copies it into the pool's pre-allocated ring with no heap allocation on
 * the hot path. `kind` selects the handler; `buf[0..len)` is the raw payload.
 */
struct Job {
    uint8_t kind{0};
    PeerId peer{-1};
    uint32_t len{0};
    std::array<uint8_t, MAX_JOB_BYTES> buf{};
};

//! Handler invoked on a worker thread for a given Job::kind. Registered once at
//! startup before Start(), so dispatch needs no lock and no per-job allocation.
using JobHandler = std::function<void(const Job&)>;

/**
 * Bounded task pool for p2p-message heavy crypto (ECIES decrypt, BLS verify,
 * range proof checks, tx combine). Net/consensus threads enqueue a POD Job and
 * return immediately; dedicated workers dispatch it to the registered handler.
 * Drop-on-overflow — callers must not assume a Job runs once Enqueue returns
 * false.
 */
class WorkerPool
{
public:
    struct Options {
        size_t num_workers{0};     // 0 = DefaultWorkerCount()
        size_t ring_capacity{0};   // 0 = DefaultRingCapacity(num_workers)
    };

    WorkerPool();
    explicit WorkerPool(Options opts);
    explicit WorkerPool(const ArgsManager& args);
    ~WorkerPool();

    WorkerPool(const WorkerPool&) = delete;
    WorkerPool& operator=(const WorkerPool&) = delete;
    WorkerPool(WorkerPool&&) = delete;
    WorkerPool& operator=(WorkerPool&&) = delete;

    //! Register the handler for a Job::kind. Must be called before Start(),
    //! from a single thread. Replaces any prior handler for that kind.
    void RegisterHandler(uint8_t kind, JobHandler handler);

    //! Spawn worker threads. Call once, after handlers are registered.
    void Start() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Copy a Job into the ring. Returns true if enqueued; returns false and
    //! increments Dropped() if the ring is full or the pool is stopping.
    bool Enqueue(const Job& job) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Signal stop, wake workers, join. Jobs still in the ring are discarded
    //! and counted as dropped. Idempotent.
    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t NumWorkers() const { return m_workers.size(); }
    size_t RingCapacity() const { return m_capacity; }
    size_t RingSize() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    uint64_t Submitted() const { return m_submitted.load(std::memory_order_relaxed); }
    uint64_t Completed() const { return m_completed.load(std::memory_order_relaxed); }
    uint64_t Dropped() const { return m_dropped.load(std::memory_order_relaxed); }

private:
    void WorkerLoop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    const size_t m_num_workers;
    const size_t m_capacity;

    //! Handler table indexed by Job::kind. Written only before Start(); read
    //! lock-free by workers thereafter.
    std::array<JobHandler, 256> m_handlers{};

    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    //! Pre-allocated ring buffer. head = next pop, tail = next push, count =
    //! occupied slots. All guarded by m_mutex.
    std::vector<Job> m_ring GUARDED_BY(m_mutex);
    size_t m_head GUARDED_BY(m_mutex){0};
    size_t m_count GUARDED_BY(m_mutex){0};
    bool m_started GUARDED_BY(m_mutex){false};
    bool m_stopping GUARDED_BY(m_mutex){false};
    std::vector<std::thread> m_workers;

    std::atomic<uint64_t> m_submitted{0};
    std::atomic<uint64_t> m_completed{0};
    std::atomic<uint64_t> m_dropped{0};
};

//! Default worker count = min(2, hardware_concurrency/4), clamped to >= 1.
size_t DefaultWorkerCount();

//! Ring capacity = 2 * num_workers * 64 (at least 64).
size_t DefaultRingCapacity(size_t num_workers);

//! -onionworkers=N startup arg name.
extern const char* const ARG_ONION_WORKERS;

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_WORKER_POOL_H
