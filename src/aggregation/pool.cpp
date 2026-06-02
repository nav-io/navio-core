// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <aggregation/pool.h>

#include <kernel/mempool_entry.h>
#include <primitives/block.h>

#include <atomic>

namespace aggregation {

namespace {
std::atomic<CandidatePool*> g_active_pool{nullptr};
}
void SetActivePool(CandidatePool* pool) { g_active_pool.store(pool, std::memory_order_release); }
CandidatePool* GetActivePool() { return g_active_pool.load(std::memory_order_acquire); }

size_t CandidatePool::ShardFor(const COutPoint& input)
{
    // Top byte of the prevout hash. Uniform enough for sharding.
    return static_cast<size_t>(input.hash.begin()[0]) % POOL_SHARDS;
}

size_t CandidatePool::Size() const
{
    size_t n = 0;
    for (size_t i = 0; i < POOL_SHARDS; ++i) {
        LOCK(m_shard_mutex[i]);
        n += m_shards[i].size();
    }
    return n;
}

bool CandidatePool::Contains(const COutPoint& input) const
{
    const size_t s = ShardFor(input);
    LOCK(m_shard_mutex[s]);
    return m_shards[s].count(input) > 0;
}

bool CandidatePool::AddCandidate(const CTransactionRef& candidate, int64_t peer)
{
    if (candidate == nullptr) return false;
    // Candidates are exactly one input.
    if (candidate->vin.size() != 1) return false;
    const COutPoint& input = candidate->vin[0].prevout;

    // Global cap (best-effort; Size() is a snapshot).
    if (Size() >= POOL_MAX_TOTAL) return false;

    // Per-peer cap. Reserve a slot up front; release it if the insert fails.
    {
        LOCK(m_peer_mutex);
        if (m_per_peer[peer] >= POOL_MAX_PER_PEER) return false;
        ++m_per_peer[peer];
    }

    const size_t s = ShardFor(input);
    bool inserted = false;
    {
        LOCK(m_shard_mutex[s]);
        inserted = m_shards[s].emplace(input, Entry{candidate, peer}).second;
    }

    if (!inserted) {
        // Dedupe (input already pooled): give back the per-peer slot.
        LOCK(m_peer_mutex);
        if (m_per_peer[peer] > 0) --m_per_peer[peer];
    }
    return inserted;
}

std::vector<CTransactionRef> CandidatePool::PickForAggregate(size_t max_n) const
{
    std::vector<CTransactionRef> out;
    if (max_n > POOL_MAX_COMBINED) max_n = POOL_MAX_COMBINED;
    for (size_t i = 0; i < POOL_SHARDS && out.size() < max_n; ++i) {
        LOCK(m_shard_mutex[i]);
        for (const auto& [outpoint, entry] : m_shards[i]) {
            out.push_back(entry.tx);
            if (out.size() >= max_n) break;
        }
    }
    return out;
}

bool CandidatePool::EvictByInput(const COutPoint& input)
{
    const size_t s = ShardFor(input);
    int64_t peer = -1;
    {
        LOCK(m_shard_mutex[s]);
        auto it = m_shards[s].find(input);
        if (it == m_shards[s].end()) return false;
        peer = it->second.peer;
        m_shards[s].erase(it);
    }
    LOCK(m_peer_mutex);
    if (m_per_peer[peer] > 0) --m_per_peer[peer];
    return true;
}

void CandidatePool::EvictSpentBy(const CTransaction& tx)
{
    for (const CTxIn& in : tx.vin) {
        EvictByInput(in.prevout);
    }
}

void CandidatePool::TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t)
{
    if (tx.info.m_tx) EvictSpentBy(*tx.info.m_tx);
}

void CandidatePool::BlockConnected(ChainstateRole, const std::shared_ptr<const CBlock>& block, const CBlockIndex*)
{
    if (!block) return;
    for (const CTransactionRef& tx : block->vtx) {
        if (tx) EvictSpentBy(*tx);
    }
}

} // namespace aggregation
