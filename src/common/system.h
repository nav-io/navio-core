// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_SYSTEM_H
#define BITCOIN_COMMON_SYSTEM_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <cstdint>
#include <string>

class ArgsManager;

/** Maximum number of dedicated script-checking threads allowed */
static constexpr int MAX_SCRIPTCHECK_THREADS{15};
/** -par default (number of script-checking threads, 0 = auto) */
static constexpr int DEFAULT_SCRIPTCHECK_THREADS{0};

// Application startup time (used for uptime calculation)
int64_t GetStartupTime();

void SetupEnvironment();
[[nodiscard]] bool SetupNetworking();
#ifndef WIN32
std::string ShellEscape(const std::string& arg);
#endif
#if HAVE_SYSTEM
void runCommand(const std::string& strCommand);
#endif

/**
 * Return the number of cores available on the current system.
 * @note This does count virtual cores, such as those provided by HyperThreading.
 */
int GetNumCores();

/**
 * Number of threads, the calling thread included, that a parallel job may use
 * under a -par setting of `par` on a host with `num_cores` cores. A positive
 * value is taken as given, 0 means one thread per core, and -n leaves n cores
 * free. The result is clamped to [1, MAX_SCRIPTCHECK_THREADS + 1].
 */
int ParThreadsFromSetting(int64_t par, int num_cores);

/** ParThreadsFromSetting() for this process's -par and GetNumCores(). */
int GetParThreads(const ArgsManager& args);

#endif // BITCOIN_COMMON_SYSTEM_H
