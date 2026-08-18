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

#include <chrono>

namespace aggregation {

bool CandidateRequestQueue::Add(const blsct::PublicKey& reply_key, int64_t now)
{
    LOCK(m_mutex);
    // Prune stale entries first so a full queue of expired requests cannot
    // starve fresh ones.
    std::erase_if(m_requests, [now](const auto& e) { return e.second + REQUEST_TTL_SECONDS <= now; });
    if (m_requests.size() >= REQUEST_QUEUE_CAP) return false;
    return m_requests.emplace(reply_key.GetVch(), now).second;
}

std::vector<blsct::PublicKey> CandidateRequestQueue::Claim(size_t max_n, int64_t now)
{
    LOCK(m_mutex);
    std::vector<blsct::PublicKey> out;
    for (auto it = m_requests.begin(); it != m_requests.end() && out.size() < max_n;) {
        if (it->second + REQUEST_TTL_SECONDS <= now) {
            it = m_requests.erase(it);
            continue;
        }
        blsct::PublicKey key;
        if (key.SetVch(it->first)) out.push_back(key);
        it = m_requests.erase(it);
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

} // namespace aggregation
