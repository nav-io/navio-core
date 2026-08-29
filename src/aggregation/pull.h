// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AGGREGATION_PULL_H
#define BITCOIN_AGGREGATION_PULL_H

#include <blsct/public_key.h>
#include <sync.h>

#include <condition_variable>
#include <functional>
#include <cstdint>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

namespace p2pmsg {
class Transport;
} // namespace p2pmsg

namespace aggregation {

class CandidatePool;

//! Seconds between background pull rounds on the requesting node.
static constexpr int64_t PULL_INTERVAL_SECONDS = 60;
//! Lifetime of one pull round's reply session key: replies arriving later than
//! this no longer decrypt (the transport prunes the key), bounding both the
//! trial-decrypt set and how long a candidate offer stays valid.
static constexpr int64_t PULL_KEY_TTL_SECONDS = 600;
//! Producer side: cap on queued, not-yet-answered pull requests.
static constexpr size_t REQUEST_QUEUE_CAP = 64;
//! Producer side: cap on queued requests per source peer. Reply keys are
//! attacker-minted (a fresh keypair per request defeats key-level dedupe by
//! design), so the only stable identity to account against is the delivering
//! peer.
static constexpr size_t REQUEST_MAX_PER_PEER = 4;
//! Producer side: a queued pull request older than this is stale (its reply
//! key has expired on the requester) and is pruned instead of answered.
static constexpr int64_t REQUEST_TTL_SECONDS = PULL_KEY_TTL_SECONDS;
//! Default for -servecandidates: ON, so a stock naviod with a loaded BLSCT
//! wallet keeps the network's aggregation pools supplied. Serving hands out
//! signed self-spends of real wallet coins -- each a proof of ownership of a
//! specific on-chain output to its requester -- so the serving side is
//! bounded against enumeration (per-peer request caps, FIFO claim order, a
//! per-input reservation TTL and the rolling SERVE_MAX_COINS_PER_WINDOW
//! budget) and operators can opt out with -servecandidates=0.
static constexpr bool DEFAULT_SERVE_CANDIDATES{true};
//! Seconds between the wallet's built-in candidate-serving ticks.
static constexpr int64_t SERVE_INTERVAL_SECONDS = 20;
//! Cap on requests answered per built-in serving tick, bounding the work
//! spent building/encrypting/PoW-stamping candidates.
static constexpr size_t SERVE_MAX_PER_TICK = 2;
//! Rolling-window budget on DISTINCT coins a wallet will reveal through
//! served candidates, independent of the per-reservation TTL. Without it a
//! puller that keeps minting fresh reply keys walks a wallet's coin set at
//! SERVE_MAX_PER_TICK per tick; with it enumeration saturates at this many
//! coins per window regardless of request volume.
static constexpr size_t SERVE_MAX_COINS_PER_WINDOW = 30;
static constexpr int64_t SERVE_WINDOW_SECONDS = 60 * 60;

/**
 * Producer-side queue of candidate pull requests (AGG_ANN) awaiting a wallet
 * reply. The node's AGG_ANN handler enqueues the requester's fresh reply
 * pubkey; the candidate-serving daemon claims entries over RPC and answers
 * each with a CANDIDATE_TX built by the wallet, encrypted 1:1 to the reply
 * key. Bounded and deduplicated; entries expire with the requester's key TTL.
 */
class CandidateRequestQueue
{
public:
    //! Queue `reply_key` delivered by `from_peer` at time `now`. Returns
    //! false (no insert) when the key is already queued, the global cap is
    //! hit, or `from_peer` already has REQUEST_MAX_PER_PEER entries queued.
    bool Add(const blsct::PublicKey& reply_key, int64_t from_peer, int64_t now) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Fetch + remove up to `max_n` non-stale requests in FIFO order on
    //! enqueue time (one-shot serve, so two polling daemons never answer the
    //! same request twice). FIFO matters: the map is keyed by requester-chosen
    //! bytes, and serving in key order would let ground keys with small
    //! prefixes both jump the queue and starve honest requests.
    std::vector<blsct::PublicKey> Claim(size_t max_n, int64_t now) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Entry {
        int64_t time;
        int64_t peer;
    };
    mutable Mutex m_mutex;
    //! reply-key bytes -> entry. Keyed by serialized key for dedupe; claim
    //! order is Entry::time, never the key.
    std::map<std::vector<unsigned char>, Entry> m_requests GUARDED_BY(m_mutex);
};

//! Process-global handle to the active request queue (set at init, cleared at
//! shutdown), mirroring SetActivePool: the wallet's built-in candidate server
//! reaches it from a WalletContext, which has no NodeContext. nullptr when
//! -p2pmsg is disabled.
void SetActiveRequestQueue(CandidateRequestQueue* queue);
CandidateRequestQueue* GetActiveRequestQueue();

class CandidateServer;
//! Process-global handle to the wallet's candidate-serving thread, so node
//! shutdown can JOIN it before the p2pmsg transport it sends through is torn
//! down (the wallet client's own stop() runs after transport teardown, which
//! is too late -- an in-flight serve tick would call Send on a destroyed
//! transport). Stop() is idempotent, so the wallet-side stop remains as a
//! backstop for non-node paths.
void SetActiveCandidateServer(CandidateServer* server);
CandidateServer* GetActiveCandidateServer();

/**
 * Requester-side background puller. Keeps the local candidate pool supplied
 * without ever revealing its contents: each round it generates a FRESH reply
 * keypair, registers it with the transport (bounded TTL), and broadcasts an
 * AGG_ANN pull request carrying only the reply pubkey. Producers answer 1:1,
 * encrypted to that key, so only this node learns which candidates it holds --
 * a bus observer cannot subtract the cover halves out of a later aggregate.
 * Runs on its own thread because Transport::Send grinds proof-of-work.
 */
class CandidatePuller
{
public:
    CandidatePuller(p2pmsg::Transport& transport, const CandidatePool& pool, int64_t interval_seconds);
    ~CandidatePuller();

    CandidatePuller(const CandidatePuller&) = delete;
    CandidatePuller& operator=(const CandidatePuller&) = delete;

    void Start();
    void Stop();

    //! One pull round (fresh key + AGG_ANN broadcast), skipped when the pool
    //! already holds POOL_TARGET candidates. Public for tests.
    void PullOnce();

private:
    p2pmsg::Transport& m_transport;
    const CandidatePool& m_pool;
    const int64_t m_interval;

    std::thread m_thread;
    std::mutex m_stop_mutex;
    std::condition_variable m_stop_cv;
    bool m_stopping{false};
};

/**
 * Owns the thread the built-in candidate server runs on. Serving grinds
 * proof-of-work per reply (Transport::Send), which must not run on the node's
 * single scheduler thread -- the same rationale CandidatePuller documents for
 * the requester side.
 */
class CandidateServer
{
public:
    CandidateServer(std::function<void()> serve_tick, int64_t interval_seconds);
    ~CandidateServer();

    CandidateServer(const CandidateServer&) = delete;
    CandidateServer& operator=(const CandidateServer&) = delete;

    void Start();
    void Stop();

private:
    const std::function<void()> m_serve_tick;
    const int64_t m_interval;

    std::thread m_thread;
    std::mutex m_stop_mutex;
    std::condition_variable m_stop_cv;
    bool m_stopping{false};
};

} // namespace aggregation

#endif // BITCOIN_AGGREGATION_PULL_H
