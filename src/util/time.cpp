// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <compat/compat.h>
#include <tinyformat.h>
#include <util/time.h>
#include <util/check.h>

#include <array>
#include <atomic>
#include <chrono>
#include <ctime>
#include <locale>
#include <thread>
#include <sstream>
#include <string>
#include <string_view>

static constexpr std::array<std::string_view, 7> weekdays{"Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"}; // 1970-01-01 was a Thursday.
static constexpr std::array<std::string_view, 12> months{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

void UninterruptibleSleep(const std::chrono::microseconds& n) { std::this_thread::sleep_for(n); }

static std::atomic<int64_t> nMockTime(0); //!< For testing
static std::atomic<std::chrono::milliseconds> g_mock_steady_time{}; //!< For testing

bool ChronoSanityCheck()
{
    // std::chrono::system_clock.time_since_epoch and time_t(0) are not guaranteed
    // to use the Unix epoch timestamp, prior to C++20, but in practice they almost
    // certainly will. Any differing behavior will be assumed to be an error, unless
    // certain platforms prove to consistently deviate, at which point we'll cope
    // with it by adding offsets.

    // Create a new clock from time_t(0) and make sure that it represents 0
    // seconds from the system_clock's time_since_epoch. Then convert that back
    // to a time_t and verify that it's the same as before.
    const time_t time_t_epoch{};
    auto clock = std::chrono::system_clock::from_time_t(time_t_epoch);
    if (std::chrono::duration_cast<std::chrono::seconds>(clock.time_since_epoch()).count() != 0) {
        return false;
    }

    time_t time_val = std::chrono::system_clock::to_time_t(clock);
    if (time_val != time_t_epoch) {
        return false;
    }

    // Check that the above zero time is actually equal to the known unix timestamp.
    struct tm epoch;
#ifdef HAVE_GMTIME_R
    if (gmtime_r(&time_val, &epoch) == nullptr) {
#else
    if (gmtime_s(&epoch, &time_val) != 0) {
#endif
        return false;
    }

    if ((epoch.tm_sec != 0)  ||
       (epoch.tm_min  != 0)  ||
       (epoch.tm_hour != 0)  ||
       (epoch.tm_mday != 1)  ||
       (epoch.tm_mon  != 0)  ||
       (epoch.tm_year != 70)) {
        return false;
    }
    return true;
}

NodeClock::time_point NodeClock::now() noexcept
{
    const std::chrono::seconds mocktime{nMockTime.load(std::memory_order_relaxed)};
    const auto ret{
        mocktime.count() ?
            mocktime :
            std::chrono::system_clock::now().time_since_epoch()};
    assert(ret > 0s);
    return time_point{ret};
};

void SetMockTime(int64_t nMockTimeIn)
{
    Assert(nMockTimeIn >= 0);
    nMockTime.store(nMockTimeIn, std::memory_order_relaxed);
}

void SetMockTime(std::chrono::seconds mock_time_in)
{
    nMockTime.store(mock_time_in.count(), std::memory_order_relaxed);
}

std::chrono::seconds GetMockTime()
{
    return std::chrono::seconds(nMockTime.load(std::memory_order_relaxed));
}

MockableSteadyClock::time_point MockableSteadyClock::now() noexcept
{
    const auto mocktime{g_mock_steady_time.load(std::memory_order_relaxed)};
    const auto ret{
        mocktime.count() ?
            mocktime :
            std::chrono::steady_clock::now().time_since_epoch()};
    return time_point{ret};
};

void MockableSteadyClock::SetMockTime(std::chrono::milliseconds mock_time_in)
{
    Assert(mock_time_in >= 0s);
    g_mock_steady_time.store(mock_time_in, std::memory_order_relaxed);
}

void MockableSteadyClock::ClearMockTime()
{
    g_mock_steady_time.store(0ms, std::memory_order_relaxed);
}

int64_t GetTime() { return GetTime<std::chrono::seconds>().count(); }

std::string FormatISO8601DateTime(int64_t nTime) {
    struct tm ts;
    time_t time_val = nTime;
#ifdef HAVE_GMTIME_R
    if (gmtime_r(&time_val, &ts) == nullptr) {
#else
    if (gmtime_s(&ts, &time_val) != 0) {
#endif
        return {};
    }
    return strprintf("%04i-%02i-%02iT%02i:%02i:%02iZ", ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);
}

std::string FormatISO8601Date(int64_t nTime) {
    struct tm ts;
    time_t time_val = nTime;
#ifdef HAVE_GMTIME_R
    if (gmtime_r(&time_val, &ts) == nullptr) {
#else
    if (gmtime_s(&ts, &time_val) != 0) {
#endif
        return {};
    }
    return strprintf("%04i-%02i-%02i", ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday);
}

std::string FormatRFC1123DateTime(int64_t time)
{
    if (time < -62167219200 || 253402300799 < time) {
        // 4-digit year, so only support years 0 to 9999
        return "";
    }
    const std::chrono::sys_seconds secs{std::chrono::seconds{time}};
    const auto days{std::chrono::floor<std::chrono::days>(secs)};
    const auto w{days.time_since_epoch().count() % 7}; // will be in the range [-6, 6]
    std::string_view weekday{weekdays.at(w >= 0 ? w : w + 7)};
    const std::chrono::year_month_day ymd{days};
    std::string_view month{months.at(unsigned{ymd.month()} - 1)};
    const std::chrono::hh_mm_ss hms{secs - days};
    // examples: Mon, 27 Jul 2009 12:28:53 GMT
    //           Fri, 31 May 2024 19:18:04 GMT
    return strprintf("%03s, %02u %03s %04i %02i:%02i:%02i GMT", weekday, unsigned{ymd.day()}, month, signed{ymd.year()}, hms.hours().count(), hms.minutes().count(), hms.seconds().count());
}

struct timeval MillisToTimeval(int64_t nTimeout)
{
    struct timeval timeout;
    timeout.tv_sec  = nTimeout / 1000;
    timeout.tv_usec = (nTimeout % 1000) * 1000;
    return timeout;
}

struct timeval MillisToTimeval(std::chrono::milliseconds ms)
{
    return MillisToTimeval(count_milliseconds(ms));
}
