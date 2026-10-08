// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <chainparamsbase.h>
#include <common/args.h>
#include <i2pd_process.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/string.h>
#include <util/threadnames.h>
#include <util/translation.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#ifdef WIN32
#include <codecvt>
#include <locale>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <csignal>
#endif

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

namespace {

//! Address the managed i2pd's SAM bridge listens on and naviod connects to;
//! the port is -i2pdsamport.
const std::string I2PD_SAM_HOST{"127.0.0.1"};

#ifndef WIN32
//! Descriptor bound the child closes up to when the parent cannot read one
//! from sysconf(_SC_OPEN_MAX) (unlimited or indeterminate).
constexpr int FALLBACK_MAX_FD{65536};
#endif

//! How long shutdown waits for the router to exit after asking it to, before
//! killing it outright so that a hung router cannot stall naviod's shutdown.
//! i2pd only acts on SIGTERM once its own startup has returned, and on a first
//! run that startup includes reseeding, which takes as long as reseed servers do.
constexpr auto I2PD_STOP_TIMEOUT{std::chrono::seconds{10}};

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
//! Set by the supervisor thread once it has reaped the router and is exiting.
bool g_supervisor_done{false};
std::thread g_thread;
std::string g_exe;
std::vector<std::string> g_args;
#ifdef WIN32
//! g_exe and g_args as CreateProcessW() takes them, built once alongside them.
std::wstring g_wexe;
std::wstring g_wcmdline;
//! Job object the router runs in, so that Windows kills it when naviod exits
//! without stopping it (crash, TerminateProcess), the way PR_SET_PDEATHSIG
//! does on Linux. Null if one could not be set up.
HANDLE g_job{nullptr};
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

//! Whether `p` is something to run as the router: a regular file (after
//! following symlinks) that, on POSIX, this process may execute.
bool IsExecutableFile(const fs::path& p) noexcept
{
    std::error_code ec;
    if (!fs::is_regular_file(p, ec)) return false;
#ifdef WIN32
    return true;
#else
    return access(p.c_str(), X_OK) == 0;
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
            if (IsExecutableFile(candidate)) return candidate;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return {};
}

//! Locate the i2pd binary: explicit -i2pdcmd, then the bundled one next to
//! naviod (where both the build tree and an install put it), then $PATH.
//! An error if -i2pdcmd names nothing runnable, empty if there is no
//! -i2pdcmd and no router was found.
util::Result<fs::path> FindI2pd(const ArgsManager& args)
{
#ifdef WIN32
    const std::string name{"i2pd.exe"};
#else
    const std::string name{"i2pd"};
#endif
    const std::string configured{args.GetArg("-i2pdcmd", "")};
    if (!configured.empty()) {
        const fs::path p{fs::PathFromString(configured)};
        if (fs::PathToString(p.filename()) != configured) { // an explicit path
            if (!IsExecutableFile(p)) return util::Error{strprintf(_("-i2pdcmd '%s' is not an executable file."), configured)};
            return p;
        }
        // A bare name only ever means a PATH lookup: handed to execv() as is,
        // it would run a file of that name from the working directory instead.
        const fs::path found{SearchPath(configured)};
        if (found.empty()) return util::Error{strprintf(_("-i2pdcmd '%s' was not found in PATH."), configured)};
        return found;
    }

    const fs::path exe{GetExecutablePath()};
    if (!exe.empty()) {
        const fs::path next{exe.parent_path() / name};
        if (IsExecutableFile(next)) return next;
    }
    return SearchPath(name);
}

//! Reseed/family certificates for the router at `i2pd`, at ../share/i2pd/
//! certificates relative to it: where depends stages and naviod installs the
//! bundled router's, and where Debian and Fedora packages put a system one's.
fs::path FindCertsDir(const fs::path& i2pd)
{
    const fs::path certs{i2pd.parent_path().parent_path() / "share" / "i2pd" / "certificates"};
    return Exists(certs) ? certs : fs::path{};
}

#ifdef WIN32
//! UTF-8 to UTF-16, converted as the rest of the tree does for wide Win32 APIs.
std::wstring ToWide(const std::string& utf8)
{
    return std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t>().from_bytes(utf8);
}

//! Append `arg` to a Windows command line so that the child's C runtime and
//! CommandLineToArgvW() split it back out as exactly `arg`. Under their rules a
//! run of backslashes is literal unless a double quote follows it; then each
//! pair stands for one backslash and an odd one left over escapes the quote.
//! So the argument is wrapped in quotes, embedded quotes are escaped, and the
//! backslashes in front of an embedded or the closing quote are doubled.
void AppendQuotedArg(std::wstring& cmdline, const std::wstring& arg)
{
    if (!cmdline.empty()) cmdline += L' ';
    cmdline += L'"';
    size_t backslashes{0};
    for (const wchar_t c : arg) {
        if (c == L'\\') {
            ++backslashes;
            continue;
        }
        cmdline.append(c == L'"' ? backslashes * 2 + 1 : backslashes, L'\\');
        backslashes = 0;
        cmdline += c;
    }
    cmdline.append(backslashes * 2, L'\\');
    cmdline += L'"';
}

//! Create the kill-on-close job object for the router. If naviod already runs
//! in a job (a service host, a terminal, a CI runner), the new job nests inside
//! it, which Windows supports since Windows 8.
HANDLE CreateKillOnCloseJob()
{
    HANDLE job{CreateJobObjectW(nullptr, nullptr)};
    if (!job) return nullptr;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        CloseHandle(job);
        return nullptr;
    }
    return job;
}
#endif

//! Launch g_exe/g_args as a detached child, recording its handle. Caller holds
//! no lock; sets g_child under g_mutex.
bool SpawnChild()
{
#ifdef WIN32
    // CreateProcessW() may write to the command line buffer, so pass a copy.
    std::vector<wchar_t> mutable_cmd(g_wcmdline.begin(), g_wcmdline.end());
    mutable_cmd.push_back(L'\0');
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // Start it suspended, so that it is in the job before it runs any code and
    // so before it could start a process of its own outside the job.
    if (!CreateProcessW(g_wexe.c_str(), mutable_cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    if (g_job && !AssignProcessToJobObject(g_job, pi.hProcess)) {
        LogPrintf("i2pd: cannot add the router to its job object (error %u); it will outlive naviod if naviod crashes\n", GetLastError());
    }
    if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
        // Never left suspended: a router that cannot run would otherwise sit
        // there, and the supervisor would wait on it forever.
        LogPrintf("i2pd: cannot resume the router (error %u)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    CloseHandle(pi.hThread);
    std::lock_guard<std::mutex> lk(g_mutex);
    g_child = pi.hProcess;
    // StopI2PDProcess() may have run since the supervisor last checked
    // g_stop. Its TerminateChild() then found no child to stop, so stop this
    // one here, or the supervisor would wait on a router nothing ends.
    if (g_stop) TerminateProcess(g_child, 0);
    return true;
#else
    // Build argv in the parent: naviod is multithreaded, so the child may only
    // call async-signal-safe functions between fork() and execv(), and any
    // allocation there can deadlock on an allocator lock another thread held
    // when we forked. g_exe/g_args are written once in StartI2PDProcess()
    // before the supervisor thread starts and never mutated, so these pointers
    // stay valid for the child.
    std::vector<char*> argv;
    argv.reserve(g_args.size() + 1);
    for (const auto& a : g_args)
        argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    char* const exe{const_cast<char*>(g_exe.c_str())};

    // Read in the parent: neither is async-signal-safe to compute in the child.
    const pid_t parent{getpid()};
    const long open_max{sysconf(_SC_OPEN_MAX)};
    const int max_fd{open_max > 0 && open_max <= INT_MAX ? static_cast<int>(open_max) : FALLBACK_MAX_FD};

    // Until execv() the child still runs naviod's signal handlers, so a
    // SIGTERM from TerminateChild() landing in that window would be consumed
    // by HandleSIGTERM and the router would start anyway. Fork with every
    // signal blocked; the child resets the caught ones to their defaults
    // before unblocking, so a SIGTERM already pending then ends it.
    sigset_t all_signals, old_mask;
    sigfillset(&all_signals);
    pthread_sigmask(SIG_SETMASK, &all_signals, &old_mask);
    const pid_t pid{fork()};
    if (pid == 0) {
        struct sigaction default_action{};
        default_action.sa_handler = SIG_DFL;
        sigemptyset(&default_action.sa_mask);
        for (int sig{1}; sig < NSIG; ++sig) {
            struct sigaction current;
            if (sigaction(sig, nullptr, &current) == 0 && current.sa_handler != SIG_IGN) {
                sigaction(sig, &default_action, nullptr);
            }
        }
#ifdef __linux__
        // Have the kernel SIGTERM the router when naviod goes away without
        // running Shutdown() (crash, SIGKILL). It is delivered when the
        // forking thread exits; that is the supervisor, which only exits after
        // reaping this child. If naviod already died before prctl() took
        // effect, the child has been reparented, so exit instead of starting.
        // As with I2PD_STOP_TIMEOUT, a router still in its startup reseed only
        // exits once that is done.
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (getppid() != parent) _exit(127);
#else
        // No equivalent is used on macOS or other non-Linux systems: if
        // naviod dies without running Shutdown(), the router keeps running,
        // and keeps its SAM port, until it is stopped by hand.
        (void)parent;
#endif
        setsid();
        int devnull{open("/dev/null", O_RDWR)};
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
        }
        // Close everything else naviod has open: its sockets are not
        // close-on-exec, so an orphaned router would otherwise keep naviod's
        // P2P and RPC ports bound after naviod itself is gone.
        bool closed{false};
#if defined(__linux__) && defined(__NR_close_range)
        // One syscall instead of up to max_fd; ENOSYS before Linux 5.9. Keyed
        // on the kernel headers' __NR_ number, not glibc's SYS_ alias, which
        // glibc only defines from 2.33 on.
        closed = syscall(__NR_close_range, STDERR_FILENO + 1, ~0U, 0U) == 0;
#endif
        if (!closed) {
            for (int fd{STDERR_FILENO + 1}; fd < max_fd; ++fd) close(fd);
        }
        sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        execv(exe, argv.data());
        _exit(127);
    }
    pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
    if (pid < 0) return false;
    std::lock_guard<std::mutex> lk(g_mutex);
    g_child = pid;
    // StopI2PDProcess() may have run since the supervisor last checked
    // g_stop. Its TerminateChild() then found no child to signal, so signal
    // this one here, or the supervisor would wait on a router nothing ends.
    if (g_stop) kill(pid, SIGTERM);
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
    // Wait without reaping, unpublish the pid, and only then reap. Reaping
    // first would leave a window in which TerminateChild() could signal the
    // pid after the system had reused it for an unrelated process.
    siginfo_t info;
    while (waitid(P_PID, static_cast<id_t>(pid), &info, WEXITED | WNOWAIT) < 0 && errno == EINTR) {
    }
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_child = -1;
    }
    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
#endif
}

//! Ask the child to terminate (also wakes a blocked WaitChild()). With
//! `force`, kill it outright instead of letting it shut down cleanly.
void TerminateChild(bool force = false)
{
#ifdef WIN32
    (void)force; // TerminateProcess() is already unconditional.
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_child) TerminateProcess(g_child, 0);
#else
    std::lock_guard<std::mutex> lk(g_mutex);
    if (g_child > 0) kill(g_child, force ? SIGKILL : SIGTERM);
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
            // Best-effort: the parent only knows the fork/CreateProcess
            // succeeded, not that the router came up. A failed execv in the
            // child exits 127, which surfaces as the "router exited" line
            // below rather than as a launch failure here.
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
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_supervisor_done = true;
    }
    g_cv.notify_all();
}

} // namespace

util::Result<std::optional<std::string>> StartI2PDProcess(const ArgsManager& args)
{
    const std::optional<std::string> no_router;
    if (!args.GetBoolArg("-i2pd", DEFAULT_I2PD)) return no_router;

    const util::Result<fs::path> found{FindI2pd(args)};
    if (!found) return util::Error{util::ErrorString(found)};
    const fs::path& i2pd{*found};
    if (i2pd.empty()) {
        LogPrintf("i2pd: -i2pd is set but no i2pd binary was found (set -i2pdcmd=<path>); I2P disabled\n");
        return no_router;
    }

    const fs::path datadir{args.GetDataDirNet() / "i2pd"};
    try {
        fs::create_directories(datadir);
    } catch (const std::exception& e) {
        LogPrintf("i2pd: cannot create data dir %s: %s; I2P disabled\n", fs::PathToString(datadir), e.what());
        return no_router;
    }

    const std::string sam_port{ToString(GetI2PDSAMPort(args))};

    g_exe = fs::PathToString(i2pd);
    g_args = {
        g_exe,
        "--datadir=" + fs::PathToString(datadir),
        "--sam.enabled=true",
        "--sam.address=" + I2PD_SAM_HOST,
        "--sam.port=" + sam_port,
        // naviod only needs SAM. i2pd otherwise also opens its web console and
        // HTTP and SOCKS proxies on localhost by default, none of which naviod
        // uses and each of which any local user could reach.
        "--http.enabled=false",
        "--httpproxy.enabled=false",
        "--socksproxy.enabled=false",
        // i2pd does not verify reseed bundles' signatures by default.
        "--reseed.verify=true",
        // Bare switch: do not relay other routers' traffic (keeps the node
        // light). No --daemon, so i2pd stays in the foreground for us to manage.
        "--notransit",
        "--log=file",
        "--logfile=" + fs::PathToString(datadir / "i2pd.log"),
    };
    // Because --datadir is set, i2pd's own default certsdir is
    // <datadir>/certificates, which nothing populates.
    if (const fs::path certs{FindCertsDir(i2pd)}; !certs.empty()) {
        g_args.push_back("--certsdir=" + fs::PathToString(certs));
    } else {
        LogPrintf("i2pd: no reseed certificates next to %s; the router can only reseed if they are in %s\n",
                  g_exe, fs::PathToString(datadir / "certificates"));
    }
#ifdef WIN32
    // The narrow CreateProcessA() would read these UTF-8 strings in the ANSI
    // code page, garbling any non-ASCII path, such as a datadir under a user
    // profile with an accented name. i2pd still receives its argv from the C
    // runtime in that code page, so characters it cannot represent remain
    // out of reach; that is i2pd's limit, not one this side can lift.
    g_wexe = ToWide(g_exe);
    g_wcmdline.clear();
    for (const auto& a : g_args) AppendQuotedArg(g_wcmdline, ToWide(a));
    g_job = CreateKillOnCloseJob();
    if (!g_job) {
        LogPrintf("i2pd: cannot create a job object for the router (error %u); it will outlive naviod if naviod crashes\n", GetLastError());
    }
#endif

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_stop = false;
        g_started = true;
        g_supervisor_done = false;
    }
    g_thread = std::thread(&Supervise);

    const std::string endpoint{I2PD_SAM_HOST + ":" + sam_port};
    LogPrintf("i2pd: managing bundled router %s, SAM at %s\n", g_exe, endpoint);
    return std::optional<std::string>{endpoint};
}

uint16_t GetI2PDSAMPort(const ArgsManager& args)
{
    // Validated as a port by AppInitMain() before anything calls this.
    return static_cast<uint16_t>(args.GetIntArg("-i2pdsamport", BaseParams().I2PDSAMPort()));
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
    bool exited;
    {
        std::unique_lock<std::mutex> lk(g_mutex);
        exited = g_cv.wait_for(lk, I2PD_STOP_TIMEOUT, [] { return g_supervisor_done; });
    }
    if (!exited) {
        LogPrintf("i2pd: router did not exit within %d seconds; killing it\n", I2PD_STOP_TIMEOUT.count());
        TerminateChild(/*force=*/true);
    }
    if (g_thread.joinable()) g_thread.join();
#ifdef WIN32
    // The supervisor has reaped the router, so closing the job kills nothing.
    if (g_job) {
        CloseHandle(g_job);
        g_job = nullptr;
    }
#endif
    std::lock_guard<std::mutex> lk(g_mutex);
    g_started = false;
}
