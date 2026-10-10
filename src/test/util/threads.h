// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_THREADS_H
#define BITCOIN_TEST_UTIL_THREADS_H

#include <util/check.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <functional>
#include <optional>
#include <system_error>
#include <thread>

// Threads alive in this process, or nullopt off a Linux build, so pool sizes
// can only be observed there. A Windows binary under Wine can open the
// host's /proc/self/task too, but its count never showed the pool's workers
// (the Win64 cross-compile CI job), so only a Linux build counts.
inline std::optional<size_t> CountProcessThreads()
{
#ifdef __linux__
    std::error_code ec;
    fs::directory_iterator it{fs::path{"/proc/self/task"}, ec};
    if (ec) return std::nullopt;
    size_t n{0};
    for (; it != fs::directory_iterator{}; it.increment(ec)) {
        if (ec) return std::nullopt;
        ++n;
    }
    return n;
#else
    return std::nullopt;
#endif
}

// Boost precondition that skips a test which observes pool sizes where
// CountProcessThreads() cannot count.
inline boost::test_tools::assertion_result CanCountThreads(boost::unit_test::test_unit_id)
{
    boost::test_tools::assertion_result res{CountProcessThreads().has_value()};
    res.message() << "counting threads needs a Linux build with /proc/self/task, so pool sizes cannot be observed";
    return res;
}

// Measurements of a pool with a cap above 1 before concluding it spawned no
// worker: on a loaded host a worker can live and die between two samples,
// but not on every attempt.
constexpr int MAX_POOL_ATTEMPTS{5};

// Runs `work` while a sampler thread polls the process's thread count, and
// returns the most threads seen beyond those alive before (the sampler
// itself excluded): the extra workers the pool spawned.
inline size_t PeakExtraThreads(const std::function<void()>& work)
{
    const size_t before{*Assert(CountProcessThreads())};
    std::atomic<bool> done{false};
    size_t peak{0};
    std::thread sampler{[&] {
        while (!done.load()) {
            if (const auto n{CountProcessThreads()}) peak = std::max(peak, *n);
        }
    }};
    work();
    done = true;
    sampler.join();
    return peak > before + 1 ? peak - before - 1 : 0;
}

#endif // BITCOIN_TEST_UTIL_THREADS_H
