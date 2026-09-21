// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_H
#define BITCOIN_LOGGING_H

#include <crypto/siphash.h>
#include <threadsafety.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/string.h>
#include <util/time.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

static const bool DEFAULT_LOGTIMEMICROS = false;
static const bool DEFAULT_LOGIPS        = false;
static const bool DEFAULT_LOGTIMESTAMPS = true;
static const bool DEFAULT_LOGTHREADNAMES = false;
static const bool DEFAULT_LOGSOURCELOCATIONS = false;
static constexpr bool DEFAULT_LOGLEVELALWAYS = false;
extern const char * const DEFAULT_DEBUGLOGFILE;

extern bool fLogIPs;

struct LogCategory {
    std::string category;
    bool active;
};

namespace BCLog {
enum LogFlags : uint32_t {
    NONE = 0,
    NET = (1 << 0),
    TOR = (1 << 1),
    MEMPOOL = (1 << 2),
    HTTP = (1 << 3),
    BENCH = (1 << 4),
    ZMQ = (1 << 5),
    WALLETDB = (1 << 6),
    RPC = (1 << 7),
    ESTIMATEFEE = (1 << 8),
    ADDRMAN = (1 << 9),
    SELECTCOINS = (1 << 10),
    REINDEX = (1 << 11),
    CMPCTBLOCK = (1 << 12),
    RAND = (1 << 13),
    PRUNE = (1 << 14),
    PROXY = (1 << 15),
    MEMPOOLREJ = (1 << 16),
    LIBEVENT = (1 << 17),
    COINDB = (1 << 18),
    POPS = (1 << 19),
    LEVELDB = (1 << 20),
    VALIDATION = (1 << 21),
    I2P = (1 << 22),
    IPC = (1 << 23),
#ifdef DEBUG_LOCKCONTENTION
    LOCK = (1 << 24),
#endif
    UTIL = (1 << 25),
    BLOCKSTORAGE = (1 << 26),
    TXRECONCILIATION = (1 << 27),
    SCAN = (1 << 28),
    TXPACKAGES = (1 << 29),
    DANDELION = (1 << 30),
    ALL = ~(uint32_t)0,
};
    enum class Level {
        Trace = 0, // High-volume or detailed logging for development/debugging
        Debug,     // Reasonably noisy logging, but still usable in production
        Info,      // Default
        Warning,
        Error,
    };
    constexpr auto DEFAULT_LOG_LEVEL{Level::Debug};
    constexpr uint64_t RATELIMIT_MAX_BYTES{1024 * 1024}; // maximum number of bytes per source location that can be logged within the RATELIMIT_WINDOW
    constexpr auto RATELIMIT_WINDOW{1h}; // time window after which log ratelimit stats are reset
    constexpr bool DEFAULT_LOGRATELIMIT{true};

    //! A logging call site. Rate limiting keeps separate accounting per call site.
    struct SourceLocation {
        std::string file;
        int line;
        bool operator==(const SourceLocation&) const = default;
    };

    struct SourceLocationHasher {
        size_t operator()(const SourceLocation& s) const noexcept
        {
            // Use CSipHasher(0, 0) as a simple way to get uniform distribution.
            return size_t(CSipHasher(0, 0)
                              .Write(static_cast<uint64_t>(s.line))
                              .Write(MakeUCharSpan(std::string_view{s.file}))
                              .Finalize());
        }
    };

    //! Fixed window rate limiter for logging.
    class LogRateLimiter
    {
    public:
        //! Keeps track of an individual source location and how many available bytes are left for logging from it.
        struct Stats {
            //! Remaining bytes
            uint64_t m_available_bytes;
            //! Number of bytes that were consumed but didn't fit in the available bytes.
            uint64_t m_dropped_bytes{0};

            Stats(uint64_t max_bytes) : m_available_bytes{max_bytes} {}
            //! Updates internal accounting and returns true if enough available_bytes were remaining
            bool Consume(uint64_t bytes);
        };

    private:
        mutable StdMutex m_mutex;

        //! Stats for each source location that has attempted to log something.
        std::unordered_map<SourceLocation, Stats, SourceLocationHasher> m_source_locations GUARDED_BY(m_mutex);
        //! Whether any log locations are suppressed. Cached view on m_source_locations for performance reasons.
        std::atomic<bool> m_suppression_active{false};
        LogRateLimiter(uint64_t max_bytes, std::chrono::seconds reset_window);

    public:
        using SchedulerFunction = std::function<void(std::function<void()>, std::chrono::milliseconds)>;
        /**
         * @param scheduler_func    Callable object used to schedule resetting the window. The first
         *                          parameter is the function to be executed, and the second is the
         *                          reset_window interval.
         * @param max_bytes         Maximum number of bytes that can be logged for each source
         *                          location.
         * @param reset_window      Time window after which the stats are reset.
         */
        static std::shared_ptr<LogRateLimiter> Create(
            SchedulerFunction&& scheduler_func,
            uint64_t max_bytes,
            std::chrono::seconds reset_window);
        //! Maximum number of bytes logged per location per window.
        const uint64_t m_max_bytes;
        //! Interval after which the window is reset.
        const std::chrono::seconds m_reset_window;
        //! Suppression status of a source log location.
        enum class Status {
            UNSUPPRESSED,     // string fits within the limit
            NEWLY_SUPPRESSED, // suppression has started since this string
            STILL_SUPPRESSED, // suppression is still ongoing
        };
        //! Consumes `source_loc`'s available bytes corresponding to the size of the (formatted)
        //! `str` and returns its status.
        [[nodiscard]] Status Consume(
            const SourceLocation& source_loc,
            const std::string& str) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
        //! Resets all usage to zero. Called periodically by the scheduler.
        void Reset() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
        //! Returns true if any log locations are currently being suppressed.
        bool SuppressionsActive() const { return m_suppression_active; }
    };

    class Logger
    {
    private:
        mutable StdMutex m_cs; // Can not use Mutex from sync.h because in debug mode it would cause a deadlock when a potential deadlock was detected

        FILE* m_fileout GUARDED_BY(m_cs) = nullptr;
        std::list<std::string> m_msgs_before_open GUARDED_BY(m_cs);
        bool m_buffering GUARDED_BY(m_cs) = true; //!< Buffer messages before logging can be started.

        /**
         * m_started_new_line is a state variable that will suppress printing of
         * the timestamp when multiple calls are made that don't end in a
         * newline.
         */
        std::atomic_bool m_started_new_line{true};

        //! Category-specific log level. Overrides `m_log_level`.
        std::unordered_map<LogFlags, Level> m_category_log_levels GUARDED_BY(m_cs);

        //! If there is no category-specific log level, all logs with a severity
        //! level lower than `m_log_level` will be ignored.
        std::atomic<Level> m_log_level{DEFAULT_LOG_LEVEL};

        /** Log categories bitfield. */
        std::atomic<uint32_t> m_categories{0};

        std::string LogTimestampStr(const std::string& str);

        /** Slots that connect to the print signal */
        std::list<std::function<void(const std::string&)>> m_print_callbacks GUARDED_BY(m_cs) {};

        //! Manages the rate limiting of each log location.
        std::shared_ptr<LogRateLimiter> m_limiter GUARDED_BY(m_cs);

        /** Send a string to the log output (internal) */
        void LogPrintStr_(const std::string& str, const std::string& logging_function, const std::string& source_file, int source_line, BCLog::LogFlags category, BCLog::Level level, bool should_ratelimit)
            EXCLUSIVE_LOCKS_REQUIRED(m_cs);

    public:
        bool m_print_to_console = false;
        bool m_print_to_file = false;

        bool m_log_timestamps = DEFAULT_LOGTIMESTAMPS;
        bool m_log_time_micros = DEFAULT_LOGTIMEMICROS;
        bool m_log_threadnames = DEFAULT_LOGTHREADNAMES;
        bool m_log_sourcelocations = DEFAULT_LOGSOURCELOCATIONS;
        bool m_always_print_category_level = DEFAULT_LOGLEVELALWAYS;

        fs::path m_file_path;
        std::atomic<bool> m_reopen_file{false};

        std::string GetLogPrefix(LogFlags category, Level level) const;

        /** Send a string to the log output */
        void LogPrintStr(const std::string& str, const std::string& logging_function, const std::string& source_file, int source_line, BCLog::LogFlags category, BCLog::Level level, bool should_ratelimit)
            EXCLUSIVE_LOCKS_REQUIRED(!m_cs);

        /** Returns whether logs will be written to any output */
        bool Enabled() const
        {
            StdLockGuard scoped_lock(m_cs);
            return m_buffering || m_print_to_console || m_print_to_file || !m_print_callbacks.empty();
        }

        /** Connect a slot to the print signal and return the connection */
        std::list<std::function<void(const std::string&)>>::iterator PushBackCallback(std::function<void(const std::string&)> fun)
        {
            StdLockGuard scoped_lock(m_cs);
            m_print_callbacks.push_back(std::move(fun));
            return --m_print_callbacks.end();
        }

        /** Delete a connection */
        void DeleteCallback(std::list<std::function<void(const std::string&)>>::iterator it)
        {
            StdLockGuard scoped_lock(m_cs);
            m_print_callbacks.erase(it);
        }

        /** Start logging (and flush all buffered messages) */
        bool StartLogging();

        void SetRateLimiting(std::shared_ptr<LogRateLimiter> limiter) EXCLUSIVE_LOCKS_REQUIRED(!m_cs)
        {
            StdLockGuard scoped_lock(m_cs);
            m_limiter = std::move(limiter);
        }
        /** Only for testing */
        void DisconnectTestLogger();

        void ShrinkDebugFile();

        std::unordered_map<LogFlags, Level> CategoryLevels() const
        {
            StdLockGuard scoped_lock(m_cs);
            return m_category_log_levels;
        }
        void SetCategoryLogLevel(const std::unordered_map<LogFlags, Level>& levels)
        {
            StdLockGuard scoped_lock(m_cs);
            m_category_log_levels = levels;
        }
        bool SetCategoryLogLevel(const std::string& category_str, const std::string& level_str);

        Level LogLevel() const { return m_log_level.load(); }
        void SetLogLevel(Level level) { m_log_level = level; }
        bool SetLogLevel(const std::string& level);

        uint32_t GetCategoryMask() const { return m_categories.load(); }

        void EnableCategory(LogFlags flag);
        bool EnableCategory(const std::string& str);
        void DisableCategory(LogFlags flag);
        bool DisableCategory(const std::string& str);

        bool WillLogCategory(LogFlags category) const;
        bool WillLogCategoryLevel(LogFlags category, Level level) const;

        /** Returns a vector of the log categories in alphabetical order. */
        std::vector<LogCategory> LogCategoriesList() const;
        /** Returns a string with the log categories in alphabetical order. */
        std::string LogCategoriesString() const
        {
            return Join(LogCategoriesList(), ", ", [&](const LogCategory& i) { return i.category; });
        };

        //! Returns a string with all user-selectable log levels.
        std::string LogLevelsString() const;

        //! Returns the string representation of a log level.
        static std::string LogLevelToStr(BCLog::Level level);

        bool DefaultShrinkDebugFile() const;
    };

} // namespace BCLog

BCLog::Logger& LogInstance();

/** Return true if log accepts specified category, at the specified level. */
static inline bool LogAcceptCategory(BCLog::LogFlags category, BCLog::Level level)
{
    return LogInstance().WillLogCategoryLevel(category, level);
}

/** Return true if str parses as a log category and set the flag */
bool GetLogCategory(BCLog::LogFlags& flag, const std::string& str);

template <typename... Args>
static inline void LogPrintf_(const std::string& logging_function, const std::string& source_file, const int source_line, const BCLog::LogFlags flag, const BCLog::Level level, bool should_ratelimit, const char* fmt, const Args&... args)
{
    if (LogInstance().Enabled()) {
        std::string log_msg;
        try {
            log_msg = tfm::format(fmt, args...);
        } catch (tinyformat::format_error& fmterr) {
            /* Original format string will have newline so don't add one here */
            log_msg = "Error \"" + std::string(fmterr.what()) + "\" while formatting log message: " + fmt;
        }
        LogInstance().LogPrintStr(log_msg, logging_function, source_file, source_line, flag, level, should_ratelimit);
    }
}

#define LogPrintLevel_(category, level, should_ratelimit, ...) LogPrintf_(__func__, __FILE__, __LINE__, category, level, should_ratelimit, __VA_ARGS__)

// Log unconditionally. Uses basic rate limiting to mitigate disk filling attacks.
// Be conservative when using functions that unconditionally log to debug.log!
// It should not be the case that an inbound peer can fill up a user's storage
// with debug.log entries.
#define LogInfo(...) LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Info, /*should_ratelimit=*/true, __VA_ARGS__)
#define LogWarning(...) LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Warning, /*should_ratelimit=*/true, __VA_ARGS__)
#define LogError(...) LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Error, /*should_ratelimit=*/true, __VA_ARGS__)

// Deprecated unconditional logging.
#define LogPrintf(...) LogInfo(__VA_ARGS__)
#define LogPrintfCategory(category, ...) LogPrintLevel_(category, BCLog::Level::Info, /*should_ratelimit=*/true, __VA_ARGS__)

// Use a macro instead of a function for conditional logging to prevent
// evaluating arguments when logging for the category is not enabled.

// Log by prefixing the output with the passed category name and severity level. This can either
// log conditionally if the category is allowed or unconditionally if level >= BCLog::Level::Info
// is passed. If this function logs unconditionally, logging to disk is rate-limited. This is
// important so that callers don't need to worry about accidentally introducing a disk-fill
// vulnerability if level >= Info is used. Additionally, users specifying -debug are assumed to be
// developers or power users who are aware that -debug may cause excessive disk usage due to logging.
#define LogPrintLevel(category, level, ...)                           \
    do {                                                              \
        if (LogAcceptCategory((category), (level))) {                 \
            bool rate_limit{level >= BCLog::Level::Info};             \
            LogPrintLevel_(category, level, rate_limit, __VA_ARGS__); \
        }                                                             \
    } while (0)

// Log conditionally, prefixing the output with the passed category name.
#define LogDebug(category, ...) LogPrintLevel(category, BCLog::Level::Debug, __VA_ARGS__)
#define LogTrace(category, ...) LogPrintLevel(category, BCLog::Level::Trace, __VA_ARGS__)

// Deprecated conditional logging
#define LogPrint(category, ...)  LogDebug(category, __VA_ARGS__)

//! Format string for error(), which also records where error() was called
//! from: rate limiting is per source location, and error() must not make
//! every caller share one. The __builtin_* default arguments evaluate at the
//! call site. std::source_location would do the same, but libc++ 14 (still
//! built in CI) has no <source_location>.
struct ErrorFormat {
    const char* fmt;
    const char* function;
    const char* file;
    int line;
    ErrorFormat(const char* fmt_in, const char* function_in = __builtin_FUNCTION(), const char* file_in = __builtin_FILE(), int line_in = __builtin_LINE())
        : fmt{fmt_in}, function{function_in}, file{file_in}, line{line_in} {}
};

template <typename... Args>
bool error(ErrorFormat fmt, const Args&... args)
{
    LogPrintf_(fmt.function, fmt.file, fmt.line, BCLog::LogFlags::ALL, BCLog::Level::Info, /*should_ratelimit=*/true, "ERROR: %s\n", tfm::format(fmt.fmt, args...));
    return false;
}

#endif // BITCOIN_LOGGING_H
