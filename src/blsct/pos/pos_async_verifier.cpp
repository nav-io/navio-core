// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/pos/pos_async_verifier.h>

#include <util/threadnames.h>

#include <exception>

namespace blsct {

AsyncVerifyExecutor::AsyncVerifyExecutor(std::string thread_name) : m_thread_name(std::move(thread_name))
{
    m_worker = std::thread([this]() { WorkerLoop(); });
}

AsyncVerifyExecutor::~AsyncVerifyExecutor()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
    }
    m_cv.notify_all();
    if (m_worker.joinable()) m_worker.join();
}

void AsyncVerifyExecutor::WorkerLoop()
{
    util::ThreadRename(std::string{m_thread_name});
    while (true) {
        std::function<void()> job;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this]() { return m_shutdown || !m_queue.empty(); });
            if (m_queue.empty()) {
                // Shutdown with empty queue: exit. Any remaining queued
                // jobs at shutdown have their promises broken when ~Job
                // runs (handled by drain loop below if we ever decide to
                // run pending work to completion instead).
                return;
            }
            job = std::move(m_queue.front());
            m_queue.pop_front();
        }

        try {
            job();
        } catch (...) {
            // std::packaged_task forwards exceptions to the future. Swallow any
            // unexpected executor-level exceptions to keep the worker alive.
        }
    }
}

AsyncVerifyExecutor& GetPosAsyncVerifier()
{
    // Function-local static: constructed on first use, destroyed at
    // process exit (after main returns) which signals + joins the worker.
    static AsyncVerifyExecutor instance{"pos-verify"};
    return instance;
}

AsyncVerifyExecutor& GetAggSigAsyncVerifier()
{
    static AsyncVerifyExecutor instance{"aggsig-verify"};
    return instance;
}

} // namespace blsct
