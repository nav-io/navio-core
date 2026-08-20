// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/worker_pool.h>

#include <common/args.h>
#include <common/system.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/threadnames.h>

#include <algorithm>

namespace p2pmsg {

const char* const ARG_ONION_WORKERS = "-onionworkers";

size_t DefaultWorkerCount()
{
    const int cores = GetNumCores();
    // min(2, cores/4), but never fewer than 1.
    size_t by_quarter = cores > 0 ? static_cast<size_t>(cores) / 4 : 0;
    return std::max<size_t>(1, std::min<size_t>(2, by_quarter));
}

size_t DefaultRingCapacity(size_t num_workers)
{
    return std::max<size_t>(64, 2 * num_workers * 64);
}

static size_t ResolveWorkers(const WorkerPool::Options& opts)
{
    return opts.num_workers != 0 ? opts.num_workers : DefaultWorkerCount();
}

static size_t ResolveCapacity(const WorkerPool::Options& opts, size_t workers)
{
    return opts.ring_capacity != 0 ? opts.ring_capacity : DefaultRingCapacity(workers);
}

WorkerPool::WorkerPool(Options opts)
    : m_num_workers(ResolveWorkers(opts)),
      m_capacity(ResolveCapacity(opts, m_num_workers))
{
    m_ring.resize(m_capacity);
}

WorkerPool::WorkerPool() : WorkerPool(Options{}) {}

static WorkerPool::Options OptionsFromArgs(const ArgsManager& args)
{
    WorkerPool::Options opts;
    const int64_t n = args.GetIntArg(ARG_ONION_WORKERS, 0);
    if (n > 0) opts.num_workers = static_cast<size_t>(n);
    return opts;
}

WorkerPool::WorkerPool(const ArgsManager& args)
    : WorkerPool(OptionsFromArgs(args))
{
}

WorkerPool::~WorkerPool()
{
    Stop();
}

void WorkerPool::RegisterHandler(uint8_t kind, JobHandler handler)
{
    // Contract: handlers are registered before Start(), from a single thread,
    // so the table is published to workers via the Start() happens-before edge.
    m_handlers[kind] = std::move(handler);
}

void WorkerPool::Start()
{
    {
        LOCK(m_mutex);
        if (m_started || m_stopping) return;
        m_started = true;
    }
    m_workers.reserve(m_num_workers);
    for (size_t i = 0; i < m_num_workers; ++i) {
        m_workers.emplace_back([this, i]() {
            util::ThreadRename(strprintf("p2pmsgwrk.%i", i));
            WorkerLoop();
        });
    }
}

bool WorkerPool::Enqueue(const Job& job)
{
    {
        LOCK(m_mutex);
        if (m_stopping || m_count == m_capacity) {
            m_dropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        const size_t tail = (m_head + m_count) % m_capacity;
        m_ring[tail] = job;
        ++m_count;
        m_submitted.fetch_add(1, std::memory_order_relaxed);
    }
    m_cv.notify_one();
    return true;
}

void WorkerPool::WorkerLoop()
{
    while (true) {
        Job job;
        {
            WAIT_LOCK(m_mutex, lock);
            m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                return m_stopping || m_count > 0;
            });
            if (m_stopping && m_count == 0) return;
            job = m_ring[m_head];
            m_head = (m_head + 1) % m_capacity;
            --m_count;
        }

        const JobHandler& handler = m_handlers[job.kind];
        if (handler) {
            handler(job);
        } else {
            LogPrint(BCLog::NET, "p2pmsg: dropping job with unregistered kind=%d\n", job.kind);
        }
        m_completed.fetch_add(1, std::memory_order_relaxed);
    }
}

void WorkerPool::Stop()
{
    {
        LOCK(m_mutex);
        if (m_stopping) return;
        m_stopping = true;
        // Discard queued-but-unstarted jobs; account them as dropped.
        m_dropped.fetch_add(m_count, std::memory_order_relaxed);
        m_count = 0;
    }
    m_cv.notify_all();
    for (std::thread& t : m_workers) {
        if (t.joinable()) t.join();
    }
    m_workers.clear();
}

size_t WorkerPool::RingSize() const
{
    LOCK(m_mutex);
    return m_count;
}

} // namespace p2pmsg
