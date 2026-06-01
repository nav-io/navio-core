// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <common/url.h>
#include <compat/compat.h>
#include <logging.h>
#include <rpc/client.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/exception.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <util/tui_dashboard.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include <support/events.h>

// The navio-p2pmsg daemon is a thin JSON-RPC client (same pattern as
// navio-staker): it polls a running naviod for p2p-messaging work it should
// answer with its wallet, and replies via wallet RPCs. It holds no node or
// wallet internals — all access is over RPC — so it sidesteps the
// node-cannot-reach-wallet constraint entirely.

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

static const char DEFAULT_RPCCONNECT[] = "127.0.0.1";
static const int DEFAULT_HTTP_CLIENT_TIMEOUT = 900;
static constexpr int DEFAULT_WAIT_CLIENT_TIMEOUT = 0;
static const int CONTINUE_EXECUTION = -1;
static const char* const DEFAULT_LOGFILE = "p2pmsg.log";
static const char* const DEFAULT_COLOR_SETTING = "auto";
//! Default poll interval between work checks, seconds.
static const int DEFAULT_POLL_SECONDS = 5;

static std::string walletName;

static void SetupCliArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);

    const auto defaultBaseParams = CreateBaseChainParams(ChainType::MAIN);
    const auto testnetBaseParams = CreateBaseChainParams(ChainType::TESTNET);
    const auto signetBaseParams = CreateBaseChainParams(ChainType::SIGNET);
    const auto regtestBaseParams = CreateBaseChainParams(ChainType::REGTEST);
    const auto blsctRegtestBaseParams = CreateBaseChainParams(ChainType::BLSCTREGTEST);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-conf=<file>", strprintf("Specify configuration file. Relative paths will be prefixed by datadir location. (default: %s)", BITCOIN_CONF_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    SetupChainParamsBaseOptions(argsman);
    argsman.AddArg("-debug=<category>", "Output debugging information (default: 0).", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-debuglogfile=<file|false>", strprintf("Specify log file. Set to false to disable logging to file (default: %s)", DEFAULT_LOGFILE), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-printtoconsole", "Prints debug to stdout", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-color=<when>", strprintf("Color setting for CLI output (default: %s).", DEFAULT_COLOR_SETTING), ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcclienttimeout=<n>", strprintf("Timeout in seconds during HTTP requests, or 0 for no timeout. (default: %d)", DEFAULT_HTTP_CLIENT_TIMEOUT), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcconnect=<ip>", strprintf("Send commands to node running on <ip> (default: %s)", DEFAULT_RPCCONNECT), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpccookiefile=<loc>", "Location of the auth cookie. Relative paths will be prefixed by a net-specific datadir location. (default: data dir)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcpassword=<pw>", "Password for JSON-RPC connections", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcport=<port>", strprintf("Connect to JSON-RPC on <port> (default: %u, testnet: %u, signet: %u, regtest: %u, blsctregtest: %u)", defaultBaseParams->RPCPort(), testnetBaseParams->RPCPort(), signetBaseParams->RPCPort(), regtestBaseParams->RPCPort(), blsctRegtestBaseParams->RPCPort()), ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcuser=<user>", "Username for JSON-RPC connections", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcwait", "Wait for RPC server to start", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcwaittimeout=<n>", strprintf("Timeout in seconds to wait for the RPC server to start, or 0 for no timeout. (default: %d)", DEFAULT_WAIT_CLIENT_TIMEOUT), ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-wallet=<wallet-name>", "Wallet used to build quote replies", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-pollinterval=<n>", strprintf("Seconds between work polls (default: %d)", DEFAULT_POLL_SECONDS), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
}

static void libevent_log_cb(int severity, const char* msg)
{
    if (severity >= EVENT_LOG_ERR) {
        throw std::runtime_error(strprintf("libevent error: %s", msg));
    }
}

class CConnectionFailed : public std::runtime_error
{
public:
    explicit inline CConnectionFailed(const std::string& msg) : std::runtime_error(msg) {}
};

static int AppInitRPC(int argc, char* argv[])
{
    SetupCliArgs(gArgs);
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }
    if (HelpRequested(gArgs) || gArgs.IsArgSet("-version")) {
        std::string strUsage = PACKAGE_NAME " p2pmsg daemon version " + FormatFullVersion() + "\n";
        if (!gArgs.IsArgSet("-version")) {
            strUsage += "\nUsage:  navio-p2pmsg [options]   Run the p2p-messaging worker\n\n" + gArgs.GetHelpMessage();
        }
        tfm::format(std::cout, "%s", strUsage);
        return EXIT_SUCCESS;
    }
    if (!CheckDataDirOption(gArgs)) {
        tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", gArgs.GetArg("-datadir", ""));
        return EXIT_FAILURE;
    }
    if (!gArgs.ReadConfigFiles(error, true)) {
        tfm::format(std::cerr, "Error reading configuration file: %s\n", error);
        return EXIT_FAILURE;
    }
    try {
        SelectBaseParams(gArgs.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }
    return CONTINUE_EXECUTION;
}

struct HTTPReply {
    HTTPReply() = default;
    int status{0};
    int error{-1};
    std::string body;
};

static std::string http_errorstring(int code)
{
    switch (code) {
    case EVREQ_HTTP_TIMEOUT: return "timeout reached";
    case EVREQ_HTTP_EOF: return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER: return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR: return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL: return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG: return "response body is larger than allowed";
    default: return "unknown";
    }
}

static void http_request_done(struct evhttp_request* req, void* ctx)
{
    HTTPReply* reply = static_cast<HTTPReply*>(ctx);
    if (req == nullptr) { reply->status = 0; return; }
    reply->status = evhttp_request_get_response_code(req);
    struct evbuffer* buf = evhttp_request_get_input_buffer(req);
    if (buf) {
        size_t size = evbuffer_get_length(buf);
        const char* data = (const char*)evbuffer_pullup(buf, size);
        if (data) reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

static void http_error_cb(enum evhttp_request_error err, void* ctx)
{
    static_cast<HTTPReply*>(ctx)->error = err;
}

static UniValue CallRPC(const std::string& strMethod, const std::vector<std::string>& args,
                        const std::optional<std::string>& rpcwallet = {})
{
    std::string host;
    uint16_t port{BaseParams().RPCPort()};
    SplitHostPort(gArgs.GetArg("-rpcconnect", DEFAULT_RPCCONNECT), port, host);
    port = static_cast<uint16_t>(gArgs.GetIntArg("-rpcport", port));

    raii_event_base base = obtain_event_base();
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    {
        const int timeout = gArgs.GetIntArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT);
        evhttp_connection_set_timeout(evcon.get(), timeout > 0 ? timeout : 5 * 31556952);
    }

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == nullptr) throw std::runtime_error("create http request failed");
    evhttp_request_set_error_cb(req.get(), http_error_cb);

    std::string strRPCUserColonPass;
    bool failedToGetAuthCookie = false;
    if (gArgs.GetArg("-rpcpassword", "") == "") {
        if (!GetAuthCookie(&strRPCUserColonPass)) failedToGetAuthCookie = true;
    } else {
        strRPCUserColonPass = gArgs.GetArg("-rpcuser", "") + ":" + gArgs.GetArg("-rpcpassword", "");
    }

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Content-Type", "application/json");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    UniValue params = RPCConvertValues(strMethod, args);
    std::string strRequest = JSONRPCRequestObj(strMethod, params, 1).write() + "\n";
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    std::string endpoint = "/";
    if (rpcwallet) {
        char* encodedURI = evhttp_uriencode(rpcwallet->data(), rpcwallet->size(), false);
        if (encodedURI) { endpoint = "/wallet/" + std::string(encodedURI); free(encodedURI); }
        else throw CConnectionFailed("uri-encode failed");
    }
    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, endpoint.c_str());
    (void)req.release();
    if (r != 0) throw CConnectionFailed("send http request failed");
    event_base_dispatch(base.get());

    if (response.status == 0) {
        std::string m;
        if (response.error != -1) m = strprintf(" (error code %d - \"%s\")", response.error, http_errorstring(response.error));
        throw CConnectionFailed(strprintf("Could not connect to the server %s:%d%s", host, port, m));
    } else if (response.status == HTTP_UNAUTHORIZED) {
        throw std::runtime_error(failedToGetAuthCookie ? "Could not locate RPC credentials" : "Authorization failed");
    } else if (response.body.empty()) {
        throw std::runtime_error("no response from server");
    }

    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body)) throw std::runtime_error("couldn't parse reply from server");
    UniValue reply = valReply.get_obj();
    if (reply.empty()) throw std::runtime_error("expected reply to have result, error and id properties");
    return reply;
}

//! Connect-with-retry wrapper, used for the initial handshake.
static UniValue ConnectAndCallRPC(const std::string& strMethod, const std::vector<std::string>& args,
                                  const std::optional<std::string>& rpcwallet = {})
{
    UniValue reply(UniValue::VOBJ);
    const bool fWait = gArgs.GetBoolArg("-rpcwait", true);
    const int timeout = gArgs.GetIntArg("-rpcwaittimeout", DEFAULT_WAIT_CLIENT_TIMEOUT);
    const auto deadline{std::chrono::steady_clock::now() + 1s * timeout};
    do {
        try {
            reply = CallRPC(strMethod, args, rpcwallet);
            if (fWait) {
                const UniValue& error = reply.find_value("error");
                if (!error.isNull() && error["code"].getInt<int>() == RPC_IN_WARMUP) {
                    throw CConnectionFailed("server in warmup");
                }
            }
            break;
        } catch (const CConnectionFailed& e) {
            if (fWait && (timeout <= 0 || std::chrono::steady_clock::now() < deadline)) {
                UninterruptibleSleep(1s);
            } else {
                throw;
            }
        }
    } while (fWait);
    return reply;
}

struct PollStats {
    uint64_t cycles{0};
    uint64_t replied{0};
    uint64_t errors{0};
    uint64_t pending{0};
    std::string last_event{"starting up"};
};

//! One poll cycle: answer every matched RFQ request the node has queued.
//! Best-effort — a transient RPC error increments the counter, never throws out.
static void PollOnce(tui::Dashboard& dash, PollStats& st)
{
    const std::optional<std::string> wallet = walletName.empty() ? std::nullopt : std::optional<std::string>(walletName);
    ++st.cycles;

    UniValue pending;
    try {
        UniValue reply = CallRPC("listpendingquoterequests", {}, wallet);
        const UniValue& err = reply.find_value("error");
        if (!err.isNull()) {
            ++st.errors;
            st.last_event = "listpendingquoterequests: " + err.write();
            dash.Log(st.last_event);
            return;
        }
        pending = reply.find_value("result");
    } catch (const std::exception& e) {
        ++st.errors;
        st.last_event = std::string("poll failed: ") + e.what();
        dash.Log(st.last_event);
        return;
    }

    if (!pending.isArray()) { st.pending = 0; return; }
    st.pending = pending.size();
    for (const UniValue& p : pending.getValues()) {
        const std::string uuid = p.find_value("uuid").get_str();
        try {
            UniValue reply = CallRPC("replyquote", {uuid}, wallet);
            const UniValue& err = reply.find_value("error");
            if (!err.isNull()) {
                ++st.errors;
                st.last_event = strprintf("replyquote %s: %s", uuid.substr(0, 12), err.write());
            } else {
                ++st.replied;
                st.last_event = strprintf("replied to RFQ %s", uuid.substr(0, 12));
            }
            dash.Log(st.last_event);
        } catch (const std::exception& e) {
            ++st.errors;
            st.last_event = strprintf("replyquote %s failed: %s", uuid.substr(0, 12), e.what());
            dash.Log(st.last_event);
        }
    }
}

static std::string FmtUptime(std::chrono::seconds s)
{
    auto total = s.count();
    long h = total / 3600, m = (total % 3600) / 60, sec = total % 60;
    if (h > 0) return strprintf("%dh %dm %ds", h, m, sec);
    if (m > 0) return strprintf("%dm %ds", m, sec);
    return strprintf("%ds", sec);
}

static void Loop()
{
    const int interval = std::max(1, (int)gArgs.GetIntArg("-pollinterval", DEFAULT_POLL_SECONDS));
    tui::Dashboard dash(strprintf("navio-p2pmsg  [%s]", walletName.empty() ? "default wallet" : walletName));
    tui::RawMode raw;
    PollStats st;
    const auto start = std::chrono::steady_clock::now();
    dash.Log(strprintf("p2pmsg worker started (poll=%ds, wallet=%s)", interval, walletName));

    while (dash.State() != tui::RunState::Quitting) {
        for (char k = raw.PollKey(); k != 0; k = raw.PollKey()) {
            if (k == 'q') dash.SetState(tui::RunState::Quitting);
            else if (k == 'p') { dash.SetState(tui::RunState::Paused); dash.Log("paused by operator"); }
            else if (k == 'r') { dash.SetState(tui::RunState::Running); dash.Log("resumed by operator"); }
        }
        if (dash.State() == tui::RunState::Quitting) break;

        const bool paused = dash.State() == tui::RunState::Paused;
        if (!paused) PollOnce(dash, st);

        const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start);
        dash.SetStat("State", paused ? "paused" : "polling");
        dash.SetStat("Uptime", FmtUptime(uptime));
        dash.SetStat("Pending requests", strprintf("%d", st.pending));
        dash.SetStat("Quotes replied", strprintf("%d", st.replied));
        dash.SetStat("Poll cycles", strprintf("%d", st.cycles));
        dash.SetStat("RPC errors", strprintf("%d", st.errors));
        dash.SetStat("Last event", st.last_event);
        dash.Render();

        UninterruptibleSleep(std::chrono::seconds{interval});
    }
    dash.Log("shutting down");
    dash.Render();
}

MAIN_FUNCTION
{
#ifdef WIN32
    common::WinCmdLineArgs winArgs;
    std::tie(argc, argv) = winArgs.get();
#endif
    SetupEnvironment();
    if (!SetupNetworking()) {
        tfm::format(std::cerr, "Error: Initializing networking failed\n");
        return EXIT_FAILURE;
    }
    event_set_log_callback(&libevent_log_cb);

    try {
        int ret = AppInitRPC(argc, argv);
        if (ret != CONTINUE_EXECUTION) return ret;
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitRPC()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitRPC()");
        return EXIT_FAILURE;
    }

    walletName = gArgs.GetArg("-wallet", "");

    // Initial handshake (honours -rpcwait): confirm the node has p2pmsg enabled.
    try {
        UniValue info = ConnectAndCallRPC("getp2pmsginfo", {},
                                          walletName.empty() ? std::nullopt : std::optional<std::string>(walletName));
        const UniValue& res = info.find_value("result");
        if (!res.isObject() || !res.find_value("enabled").get_bool()) {
            tfm::format(std::cerr, "Error: the node does not have -p2pmsg enabled\n");
            return EXIT_FAILURE;
        }
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error contacting node: %s\n", e.what());
        return EXIT_FAILURE;
    }

    Loop();
    return EXIT_SUCCESS;
}
