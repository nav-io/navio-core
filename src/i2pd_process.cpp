// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <common/args.h>
#include <i2pd_process.h>
#include <logging.h>
#include <util/fs.h>
#include <util/threadnames.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

namespace {

//! SAM bridge endpoint the managed i2pd listens on and naviod connects to.
const std::string I2PD_SAM_HOST{"127.0.0.1"};
const std::string I2PD_SAM_PORT{"7656"};

//! fs::exists() that never throws, for best-effort path probing.
bool Exists(const fs::path& p) noexcept
{
    try {
        return fs::exists(p);
    } catch (...) {
        return false;
    }
}

std::mutex g_mutex;
std::condition_variable g_cv;
bool g_stop{false};
bool g_started{false};
std::thread g_thread;
std::string g_exe;
std::vector<std::string> g_args;
#ifdef WIN32
HANDLE g_child{nullptr};
#else
pid_t g_child{-1};
#endif

fs::path GetExecutablePath()
{
#ifdef WIN32
    wchar_t buf[MAX_PATH];
    DWORD len{GetModuleFileNameW(nullptr, buf, MAX_PATH)};
    if (len == 0 || len == MAX_PATH) return {};
    return fs::path(std::wstring(buf, len));
#elif defined(__APPLE__)
    char buf[4096];
    uint32_t size{sizeof(buf)};
    if (_NSGetExecutablePath(buf, &size) != 0) return {};
    std::error_code ec;
    fs::path canonical{fs::canonical(fs::path(buf), ec)};
    return ec ? fs::path(buf) : canonical;
#else
    std::error_code ec;
    fs::path exe{fs::read_symlink("/proc/self/exe", ec)};
    return ec ? fs::path{} : exe;
#endif
}

//! Search $PATH for an executable named `name`. Returns empty if not found.
fs::path SearchPath(const std::string& name)
{
    const char* path_env{std::getenv("PATH")};
    if (!path_env) return {};
#ifdef WIN32
    const char sep{';'};
#else
    const char sep{':'};
#endif
    const std::string paths{path_env};
    size_t start{0};
    while (start <= paths.size()) {
        const size_t end{paths.find(sep, start)};
        const std::string dir{paths.substr(start, end == std::string::npos ? std::string::npos : end - start)};
        if (!dir.empty()) {
            fs::path candidate{fs::PathFromString(dir)};
            candidate /= fs::PathFromString(name);
            if (Exists(candidate)) return candidate;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return {};
}

//! Locate the i2pd binary: explicit -i2pdcmd, then the bundled one (next to
//! naviod / configured at build time), then $PATH. Empty if none usable.
fs::path FindI2pd(const ArgsManager& args)
{
#ifdef WIN32
    const std::string name{"i2pd.exe"};
#else
    const std::string name{"i2pd"};
#endif
    const std::string configured{args.GetArg("-i2pdcmd", "")};
    if (!configured.empty()) {
        const fs::path p{fs::PathFromString(configured)};
        if (fs::PathToString(p.filename()) != configured) return p; // an explicit path
        const fs::path found{SearchPath(configured)};
        return found.empty() ? p : found;
    }

#ifdef BUNDLED_I2P_EXECUTABLE
    {
        const fs::path bundled{fs::PathFromString(BUNDLED_I2P_EXECUTABLE)};
        if (Exists(bundled)) return bundled;
    }
#endif
    const fs::path exe{GetExecutablePath()};
    if (!exe.empty()) {
        const fs::path next{exe.parent_path() / name};
        if (Exists(next)) return next;
    }
    return SearchPath(name);
}

//! Launch g_exe/g_args as a detached child, recording its handle. Caller holds
//! no lock; sets g_child under g_mutex.
bool SpawnChild()
{
#ifdef WIN32
    std::string cmdline;
    for (const auto& a : g_args) {
        if (!cmdline.empty()) cmdline += ' ';
        cmdline += '"' + a + '"';
    }
    std::vector<char> mutable_cmd(cmdline.begin(), cmdline.end());
    mutable_cmd.push_back('\0');
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    CloseHandle(pi.hThread);
    std::lock_guard<std::mutex> lk(g_mutex);
    g_child = pi.hProcess;
    return true;
#else
    pid_t pid{fork()};
    if (pid < 0) return false;
    if (pid == 0) {
        setsid();
        int devnull{open("/dev/null", O_RDWR)};
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        std::vector<char*> argv;
        argv.reserve(g_args.size() + 1);
        for (const auto& a : g_args)
            argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        execv(g_exe.c_str(), argv.data());
        _exit(127);
    }
    std::lock_guard<std::mutex> lk(g_mutex);
    g_child = pid;
    return true;
#endif
}

//! Block until the child exits (woken early by TerminateChild on shutdown).
void WaitChild()
{
#ifdef WIN32
    HANDLE h;
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        h = g_child;
    }
    if (!h) return;
    WaitForSingleObject(h, INFINITE);
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_child) {
        CloseHandle(g_child);
        g_child = nullptr;
    }
#else
    pid_t pid;
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        pid = g_child;
    }
    if (pid <= 0) return;
    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    std::lock_guard<std::mutex> lk(g_mutex);
    g_child = -1;
#endif
}

//! Ask the child to terminate (also wakes a blocked WaitChild()).
void TerminateChild()
{
#ifdef WIN32
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_child) TerminateProcess(g_child, 0);
#else
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_child > 0) kill(g_child, SIGTERM);
#endif
}

//! Supervisor loop: keep i2pd running, restarting with backoff, until stopped.
void Supervise()
{
    util::ThreadRename("i2pd");
    int backoff_ms{1000};
    constexpr int max_backoff_ms{30000};
    while (true) {
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (g_stop) break;
        }
        const auto launched_at{std::chrono::steady_clock::now()};
        if (!SpawnChild()) {
            LogPrintf("i2pd: failed to launch %s; retrying in %d ms\n", g_exe, backoff_ms);
        } else {
            LogPrintf("i2pd: started router %s\n", g_exe);
            WaitChild();
        }
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            if (g_stop) break;
        }
        // Reset backoff if the router stayed up for a healthy while.
        const auto ran{std::chrono::steady_clock::now() - launched_at};
        if (ran > std::chrono::seconds(30)) backoff_ms = 1000;
        LogPrintf("i2pd: router exited; restarting in %d ms\n", backoff_ms);
        std::unique_lock<std::mutex> lk(g_mutex);
        g_cv.wait_for(lk, std::chrono::milliseconds(backoff_ms), [] { return g_stop; });
        if (g_stop) break;
        backoff_ms = std::min(backoff_ms * 2, max_backoff_ms);
    }
    TerminateChild();
    WaitChild();
}

} // namespace

std::optional<std::string> StartI2PDProcess(const ArgsManager& args)
{
    if (!args.GetBoolArg("-i2pd", DEFAULT_I2PD)) return std::nullopt;

    const fs::path i2pd{FindI2pd(args)};
    if (i2pd.empty()) {
        LogPrintf("i2pd: no i2pd binary found (set -i2pdcmd= or -i2pd=0 to silence); I2P disabled\n");
        return std::nullopt;
    }

    const fs::path datadir{args.GetDataDirNet() / "i2pd"};
    try {
        fs::create_directories(datadir);
    } catch (const std::exception& e) {
        LogPrintf("i2pd: cannot create data dir %s: %s; I2P disabled\n", fs::PathToString(datadir), e.what());
        return std::nullopt;
    }

    g_exe = fs::PathToString(i2pd);
    g_args = {
        g_exe,
        "--datadir=" + fs::PathToString(datadir),
        "--sam.enabled=true",
        "--sam.address=" + I2PD_SAM_HOST,
        "--sam.port=" + I2PD_SAM_PORT,
        // Bare switch: do not relay other routers' traffic (keeps the node
        // light). No --daemon, so i2pd stays in the foreground for us to manage.
        "--notransit",
        "--log=file",
        "--logfile=" + fs::PathToString(datadir / "i2pd.log"),
    };

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_stop = false;
        g_started = true;
    }
    g_thread = std::thread(&Supervise);

    const std::string endpoint{I2PD_SAM_HOST + ":" + I2PD_SAM_PORT};
    LogPrintf("i2pd: managing bundled router %s, SAM at %s\n", g_exe, endpoint);
    return endpoint;
}

void StopI2PDProcess()
{
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (!g_started) return;
        g_stop = true;
    }
    g_cv.notify_all();
    TerminateChild();
    if (g_thread.joinable()) g_thread.join();
    std::lock_guard<std::mutex> lk(g_mutex);
    g_started = false;
}
