// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLSCT_POS_POS_ASYNC_VERIFIER_H
#define BLSCT_POS_POS_ASYNC_VERIFIER_H

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
// ----------------------------------------------------------------------
// The MCL verifier internally uses OpenMP (mclBn{G1_mulVecMT,_millerLoopVecMT})
// when compiled with MCL_USE_OMP=1. libomp lazily initialises a per-thread
// allocator/state the first time any host thread enters an OMP parallel
// region, and tears that state down via pthread-key destructors when the
// host thread exits.
//
// std::async(std::launch::async, ...) on macOS/Linux glibc typically spawns a
// fresh pthread per call, so each block we'd:
//   1. spawn a new pthread,
//   2. enter MCL's OMP region from that pthread (libomp registers + inits
//      its per-thread allocator),
//   3. exit the pthread once the future is consumed (libomp tears down).
// Concurrently the main thread is also driving its own OMP regions through
// the per-tx VerifyBatch path. The cross-thread interleaving of "new host
// thread initialising libomp TLS" with "existing host thread allocating in
// libomp" was observed to corrupt the allocator state and trip an internal
// assertion in kmp_alloc.cpp (OMP: Error #13: Assertion failure ...) after
// O(40) blocks.
//
// Pinning async verification work to long-lived worker threads:
//   - libomp initialises that thread's TLS exactly once,
//   - no teardown happens in steady state,
//   - the only other host thread regularly entering OMP is the validation
//     main thread; two stable hosts is a configuration libomp handles
//     reliably.
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

#endif // BLSCT_POS_POS_ASYNC_VERIFIER_H
