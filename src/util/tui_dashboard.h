// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TUI_DASHBOARD_H
#define BITCOIN_UTIL_TUI_DASHBOARD_H

// A dependency-free, in-place ANSI terminal dashboard for the operator daemons
// (navio-staker, navio-p2pmsg). It renders a fixed header, a key/value stats
// table, and a scrolling log pane, refreshing in place via ANSI escape codes.
// Keypresses (q / p / r) are read non-blocking from a raw-mode stdin on POSIX.
//
// When stdout is not a TTY (piped, service manager, Windows without VT), it
// degrades to plain line-by-line logging so the binaries stay usable headless.

#include <tinyformat.h>

#include <util/strencodings.h>

#include <atomic>
#include <cstdio>
#include <deque>
#include <iostream>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#ifndef WIN32
#include <termios.h>
#include <unistd.h>
#include <sys/select.h>
#endif

namespace tui {

//! Operator control state, toggled by keypresses.
enum class RunState { Running, Paused, Quitting };

inline bool StdoutIsTty()
{
#ifndef WIN32
    return ::isatty(STDOUT_FILENO) != 0;
#else
    return false;
#endif
}

//! Puts the terminal into cbreak/no-echo mode for the object's lifetime so
//! single keypresses can be read without Enter. No-op off a TTY / on Windows.
class RawMode
{
public:
    RawMode()
    {
#ifndef WIN32
        if (!StdoutIsTty()) return;
        if (tcgetattr(STDIN_FILENO, &m_orig) != 0) return;
        m_active = true;
        struct termios raw = m_orig;
        raw.c_lflag &= ~(ICANON | ECHO);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
#endif
    }
    ~RawMode()
    {
#ifndef WIN32
        if (m_active) tcsetattr(STDIN_FILENO, TCSANOW, &m_orig);
#endif
    }
    RawMode(const RawMode&) = delete;
    RawMode& operator=(const RawMode&) = delete;

    //! Return a pending keypress (lowercased) or 0 if none is buffered.
    char PollKey()
    {
#ifndef WIN32
        if (!m_active) return 0;
        char c = 0;
        ssize_t n = ::read(STDIN_FILENO, &c, 1);
        if (n == 1) return ToLower(c);
#endif
        return 0;
    }

private:
#ifndef WIN32
    struct termios m_orig{};
#endif
    bool m_active{false};
};

//! Thread-safe dashboard model + renderer. The worker thread updates stats and
//! pushes log lines; Render() repaints the screen in place.
class Dashboard
{
public:
    explicit Dashboard(std::string title, size_t log_lines = 12)
        : m_title(std::move(title)), m_max_log(log_lines), m_is_tty(StdoutIsTty()) {}

    //! Set or update a labelled stat (insertion order preserved).
    void SetStat(const std::string& key, const std::string& value)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        for (auto& kv : m_stats) {
            if (kv.first == key) { kv.second = value; return; }
        }
        m_stats.emplace_back(key, value);
    }

    //! Append a log line (also printed immediately when not a TTY).
    void Log(const std::string& line)
    {
        if (!m_is_tty) {
            tfm::format(std::cout, "%s\n", line);
            std::cout.flush();
            return;
        }
        std::lock_guard<std::mutex> lk(m_mutex);
        m_log.push_back(line);
        while (m_log.size() > m_max_log) m_log.pop_front();
    }

    void SetState(RunState s) { m_state.store(s); }
    RunState State() const { return m_state.load(); }

    //! Repaint. On a non-TTY this is a no-op (logs already streamed).
    void Render()
    {
        if (!m_is_tty) return;
        std::lock_guard<std::mutex> lk(m_mutex);

        std::string out;
        out += "\x1b[H\x1b[2J"; // cursor home + clear screen
        out += "\x1b[1;36m"; // bold cyan
        out += strprintf("== %s ==\x1b[0m  [%s]\n\n", m_title, StateStr());

        for (const auto& kv : m_stats) {
            out += strprintf("  \x1b[1m%-22s\x1b[0m %s\n", kv.first + ":", kv.second);
        }
        out += "\n\x1b[2m--- log ---------------------------------------------\x1b[0m\n";
        for (const auto& line : m_log) {
            out += "  " + line + "\n";
        }
        out += "\n\x1b[2mkeys: [q]uit  [p]ause  [r]esume\x1b[0m\n";

        ::fputs(out.c_str(), stdout);
        ::fflush(stdout);
    }

private:
    const char* StateStr() const
    {
        switch (m_state.load()) {
        case RunState::Running: return "\x1b[32mRUNNING\x1b[0m\x1b[1;36m";
        case RunState::Paused: return "\x1b[33mPAUSED\x1b[0m\x1b[1;36m";
        case RunState::Quitting: return "\x1b[31mQUITTING\x1b[0m\x1b[1;36m";
        }
        return "?";
    }

    std::string m_title;
    size_t m_max_log;
    bool m_is_tty;
    std::atomic<RunState> m_state{RunState::Running};
    mutable std::mutex m_mutex;
    std::vector<std::pair<std::string, std::string>> m_stats;
    std::deque<std::string> m_log;
};

} // namespace tui

#endif // BITCOIN_UTIL_TUI_DASHBOARD_H
