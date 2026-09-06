// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_POS_POS_ASYNC_VERIFIER_H
#define NAVIO_BLSCT_POS_POS_ASYNC_VERIFIER_H

#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

namespace blsct {

// Single-thread executor for asynchronous heavyweight BLSCT verification work
// dispatched from ConnectBlock.
//
// Why a dedicated persistent worker (instead of per-block std::async)?
//
// Historically the verifier ran on OpenMP (mcl's mulVecMT), whose runtime
// corrupted its allocator state when short-lived std::async host threads
// entered and left OMP regions concurrently with the validation thread. The
// arithmetic is now blst with explicit std::thread fan-out (no library-level
// runtime), so that hazard is gone; the persistent worker is kept because it
// is still the cheaper and more predictable shape:
//   - no per-block thread spawn/teardown on the block-connect path,
//   - one long-lived host for the verifier's own MSM worker pool,
//   - FIFO draining keeps proof verification ordered with block arrival.
//
// CONCURRENCY MODEL: ConnectBlock holds cs_main, so at most one task is
// in-flight at a time. We still queue (deque) so that hypothetically nested
// callers could submit without blocking; the worker drains FIFO.
//
// LIFETIME: process-wide singletons, accessed via GetPosAsyncVerifier() and
// GetAggSigAsyncVerifier().
// The destructor signals shutdown and joins the worker; any unfinished
// queued tasks have their promise broken (.get() will throw
// std::future_error). In practice we only enqueue while holding cs_main
// and always .get() before releasing, so the queue is empty at exit.
class AsyncVerifyExecutor
{
public:
    explicit AsyncVerifyExecutor(std::string thread_name);
    ~AsyncVerifyExecutor();

    AsyncVerifyExecutor(const AsyncVerifyExecutor&) = delete;
    AsyncVerifyExecutor& operator=(const AsyncVerifyExecutor&) = delete;

    // Hand `task` to the persistent worker. Returns a future that resolves
    // with the task's return value once the worker has executed it.
    // Thread-safe; non-blocking (returns immediately after enqueue).
    template <typename Fn>
    auto Submit(Fn task) -> std::future<std::invoke_result_t<Fn>>
    {
        using Result = std::invoke_result_t<Fn>;
        auto packaged_task = std::make_shared<std::packaged_task<Result()>>(std::move(task));
        auto future = packaged_task->get_future();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.emplace_back([packaged_task]() mutable { (*packaged_task)(); });
        }
        m_cv.notify_one();
        return future;
    }

private:
    void WorkerLoop();

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<std::function<void()>> m_queue;
    bool m_shutdown{false};
    std::thread m_worker;
    std::string m_thread_name;
};

AsyncVerifyExecutor& GetPosAsyncVerifier();
AsyncVerifyExecutor& GetAggSigAsyncVerifier();

} // namespace blsct

#endif // NAVIO_BLSCT_POS_POS_ASYNC_VERIFIER_H
