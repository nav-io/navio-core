// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <aggregation/pull.h>

#include <aggregation/pool.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/private_key.h>
#include <logging.h>
#include <p2pmsg/crypto.h>
#include <p2pmsg/transport.h>
#include <util/thread.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>

#include <atomic>

namespace aggregation {

static std::atomic<CandidateRequestQueue*> g_active_request_queue{nullptr};
void SetActiveRequestQueue(CandidateRequestQueue* queue) { g_active_request_queue.store(queue, std::memory_order_release); }
CandidateRequestQueue* GetActiveRequestQueue() { return g_active_request_queue.load(std::memory_order_acquire); }

static std::atomic<CandidateServer*> g_active_candidate_server{nullptr};
void SetActiveCandidateServer(CandidateServer* server) { g_active_candidate_server.store(server, std::memory_order_release); }
CandidateServer* GetActiveCandidateServer() { return g_active_candidate_server.load(std::memory_order_acquire); }

bool CandidateRequestQueue::Add(const blsct::PublicKey& reply_key, int64_t from_peer, int64_t now)
{
    LOCK(m_mutex);
    // Prune stale entries first so a full queue of expired requests cannot
    // starve fresh ones.
    std::erase_if(m_requests, [now](const auto& e) { return e.second.time + REQUEST_TTL_SECONDS <= now; });
    if (m_requests.size() >= REQUEST_QUEUE_CAP) return false;
    // Dedupe on the reply key binds nobody (keys are ephemeral, one per
    // request). from_peer is the relaying neighbour (pfrom.GetId()), not the
    // origin, which Dandelion hides -- so this is a per-neighbour flood cap,
    // not per-requester accounting. It still bounds what any single direct
    // connection can queue; the origin-independent enumeration bound is the
    // serve-side coin budget.
    size_t from_this_peer = 0;
    for (const auto& [_, e] : m_requests) {
        if (e.peer == from_peer && ++from_this_peer >= REQUEST_MAX_PER_PEER) return false;
    }
    return m_requests.emplace(reply_key.GetVch(), Entry{now, from_peer}).second;
}

std::vector<blsct::PublicKey> CandidateRequestQueue::Claim(size_t max_n, int64_t now)
{
    LOCK(m_mutex);
    // FIFO on enqueue time, NOT map (key) order: the key bytes are chosen by
    // the requester, so lexicographic service would be grindable.
    std::vector<std::pair<int64_t, const std::vector<unsigned char>*>> order;
    order.reserve(m_requests.size());
    for (auto it = m_requests.begin(); it != m_requests.end();) {
        if (it->second.time + REQUEST_TTL_SECONDS <= now) {
            it = m_requests.erase(it);
            continue;
        }
        order.emplace_back(it->second.time, &it->first);
        ++it;
    }
    std::sort(order.begin(), order.end(),
              [](const auto& a, const auto& b) { return a.first != b.first ? a.first < b.first : *a.second < *b.second; });
    std::vector<blsct::PublicKey> out;
    for (const auto& [_, key_bytes] : order) {
        if (out.size() >= max_n) break;
        blsct::PublicKey key;
        if (key.SetVch(*key_bytes)) out.push_back(key);
        m_requests.erase(*key_bytes);
    }
    return out;
}

size_t CandidateRequestQueue::Size() const
{
    LOCK(m_mutex);
    return m_requests.size();
}

CandidatePuller::CandidatePuller(p2pmsg::Transport& transport, const CandidatePool& pool, int64_t interval_seconds)
    : m_transport(transport), m_pool(pool), m_interval(interval_seconds)
{
}

CandidatePuller::~CandidatePuller()
{
    Stop();
}

void CandidatePuller::PullOnce()
{
    if (m_pool.Size() >= POOL_TARGET) return;

    // Fresh keypair per round: replies are encrypted 1:1 to it, and nothing
    // links one round's key to another's (or to this node's inbox identity).
    blsct::PrivateKey priv(MclScalar::Rand(/*exclude_zero=*/true));
    blsct::PublicKey pub = priv.GetPublicKey();
    const int64_t expiry = GetTime<std::chrono::seconds>().count() + PULL_KEY_TTL_SECONDS;
    m_transport.AddSessionKey(pub, priv, expiry);

    // The request body is only the reply pubkey. The request itself is a
    // public broadcast (anyone may answer); the privacy property lives in the
    // 1:1-encrypted replies, not in hiding that some node is pulling.
    m_transport.Send(p2pmsg::BroadcastPubKey(), p2pmsg::PayloadKind::AGG_ANN,
                     pub.GetVch(), /*stem=*/true);
    LogPrint(BCLog::NET, "p2pmsg: candidate pull round (pool=%u)\n", (unsigned)m_pool.Size());
}

void CandidatePuller::Start()
{
    m_thread = std::thread(&util::TraceThread, "candpull", [this] {
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(m_stop_mutex);
                if (m_stop_cv.wait_for(lock, std::chrono::seconds(m_interval), [this] { return m_stopping; })) {
                    return;
                }
            }
            // Send() grinds PoW; that is why this loop owns a thread instead of
            // borrowing the scheduler's.
            PullOnce();
        }
    });
}

void CandidatePuller::Stop()
{
    {
        std::lock_guard<std::mutex> lock(m_stop_mutex);
        m_stopping = true;
    }
    m_stop_cv.notify_all();
    if (m_thread.joinable()) m_thread.join();
}

CandidateServer::CandidateServer(std::function<void()> serve_tick, int64_t interval_seconds)
    : m_serve_tick(std::move(serve_tick)), m_interval(interval_seconds)
{
}

CandidateServer::~CandidateServer()
{
    Stop();
}

void CandidateServer::Start()
{
    m_thread = std::thread(&util::TraceThread, "candserve", [this] {
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(m_stop_mutex);
                if (m_stop_cv.wait_for(lock, std::chrono::seconds(m_interval), [this] { return m_stopping; })) {
                    return;
                }
            }
            // Send() grinds PoW per served candidate; that is why serving owns
            // a thread instead of borrowing the node scheduler's only one.
            m_serve_tick();
        }
    });
}

void CandidateServer::Stop()
{
    {
        std::lock_guard<std::mutex> lock(m_stop_mutex);
        m_stopping = true;
    }
    m_stop_cv.notify_all();
    if (m_thread.joinable()) m_thread.join();
}

} // namespace aggregation
