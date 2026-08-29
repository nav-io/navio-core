// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Management of an optionally-bundled i2pd (I2P router) child process. With
// -i2pd and no explicit -i2psam, naviod launches and supervises its own i2pd so
// that I2P reachability works without installing a router. naviod's existing
// I2P SAM client then connects to it exactly as it would to an externally-run
// router.
//
// Opt-in: -i2pd defaults to off, so a node only runs a router when asked to.
// Whether navio ships with I2P on by default is a separate decision; until it
// is made, starting a second network daemon is not something a build should do
// on the user's behalf.
//
// Robustness contract: i2pd runs as a *separate OS process* and is supervised in
// a background thread. Starting it never blocks node init, and if i2pd exits or
// crashes it is automatically restarted with backoff. A failing i2pd therefore
// can never crash or stall naviod — at worst I2P connectivity is temporarily
// unavailable while clearnet continues normally.

#ifndef BITCOIN_I2PD_PROCESS_H
#define BITCOIN_I2PD_PROCESS_H

#include <optional>
#include <string>

class ArgsManager;

/** Default for -i2pd: do not run the bundled i2pd router unless asked. */
static const bool DEFAULT_I2PD = false;

/**
 * If enabled and no explicit -i2psam is set, locate i2pd and start a background
 * supervisor that keeps it running (auto-restart on exit). Returns the SAM
 * endpoint ("host:port") naviod should use for I2P, or std::nullopt if the
 * bundled router is disabled, unavailable, or an external -i2psam is configured.
 * Never blocks waiting for i2pd to become ready.
 */
std::optional<std::string> StartI2PDProcess(const ArgsManager& args);

/** Signal the supervisor to stop and terminate the i2pd process (no-op if not started). */
void StopI2PDProcess();

#endif // BITCOIN_I2PD_PROCESS_H
