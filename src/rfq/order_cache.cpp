// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rfq/order_cache.h>

#include <kernel/mempool_entry.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <streams.h>

#include <atomic>

namespace rfq {

namespace {
std::atomic<OrderCache*> g_active_orders{nullptr};
}
void SetActiveOrderCache(OrderCache* cache) { g_active_orders.store(cache, std::memory_order_release); }
OrderCache* GetActiveOrderCache() { return g_active_orders.load(std::memory_order_acquire); }

namespace {
//! Approximate in-cache footprint of a quote. The dominant term is the half-tx;
//! GetSerializeSize on a BLSCT tx needs serialization params, so we use its
//! virtual size as a proxy plus a fixed allowance for the quote's scalar fields.
size_t QuoteBytes(const RfqQuote& q)
{
    size_t n = 256; // uuid, quote_id, amounts, expiry, pubkey, sig
    if (q.half_tx) n += static_cast<size_t>(::GetVirtualTransactionSize(*q.half_tx));
    return n;
}
} // namespace

OrderCache::OrderCache(int64_t) {}

void OrderCache::TouchLRU(const uint256& quote_id)
{
    auto pit = m_lru_pos.find(quote_id);
    if (pit != m_lru_pos.end()) m_lru.erase(pit->second);
    m_lru.push_front(quote_id);
    m_lru_pos[quote_id] = m_lru.begin();
}

void OrderCache::EraseLocked(const uint256& quote_id)
{
    auto it = m_orders.find(quote_id);
    if (it == m_orders.end()) return;
    m_bytes -= it->second.bytes;
    if (it->second.quote.half_tx) {
        for (const CTxIn& in : it->second.quote.half_tx->vin) {
            auto bi = m_by_input.find(in.prevout);
            if (bi != m_by_input.end() && bi->second == quote_id) m_by_input.erase(bi);
        }
    }
    auto pit = m_lru_pos.find(quote_id);
    if (pit != m_lru_pos.end()) {
        m_lru.erase(pit->second);
        m_lru_pos.erase(pit);
    }
    m_orders.erase(it);
}

void OrderCache::EvictToBound()
{
    while (m_bytes > MAX_ORDER_CACHE_BYTES && !m_lru.empty()) {
        EraseLocked(m_lru.back());
    }
}

bool OrderCache::StoreOrder(const RfqQuote& q, int64_t now)
{
    if (!q.half_tx) return false;
    if (q.order_expiry <= now) return false;

    LOCK(m_mutex);
    if (m_orders.count(q.quote_id)) return false;

    Entry e;
    e.quote = q;
    e.effective_expiry = std::min<int64_t>(q.order_expiry, now + MAX_ORDER_TTL_SECONDS);
    e.bytes = QuoteBytes(q);

    m_bytes += e.bytes;
    for (const CTxIn& in : q.half_tx->vin) {
        m_by_input[in.prevout] = q.quote_id;
    }
    m_orders.emplace(q.quote_id, std::move(e));
    TouchLRU(q.quote_id);
    EvictToBound();
    return m_orders.count(q.quote_id) > 0; // false if immediately evicted (oversized)
}

std::vector<RfqQuote> OrderCache::FindMatching(const RfqRequest& req, int64_t now)
{
    std::vector<RfqQuote> out;
    LOCK(m_mutex);
    for (auto it = m_orders.begin(); it != m_orders.end();) {
        if (it->second.effective_expiry <= now) {
            const uint256 id = it->first;
            ++it;
            EraseLocked(id);
            continue;
        }
        const RfqQuote& q = it->second.quote;
        // Coarse match: the order must at least deliver the requested buy token
        // in an amount that can cover the request size. The taker re-validates.
        if (q.fill >= req.size) {
            out.push_back(q);
            TouchLRU(it->first);
        }
        ++it;
    }
    return out;
}

size_t OrderCache::PruneExpired(int64_t now)
{
    LOCK(m_mutex);
    size_t removed = 0;
    for (auto it = m_orders.begin(); it != m_orders.end();) {
        if (it->second.effective_expiry <= now) {
            const uint256 id = it->first;
            ++it;
            EraseLocked(id);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

size_t OrderCache::Size() const { LOCK(m_mutex); return m_orders.size(); }
size_t OrderCache::Bytes() const { LOCK(m_mutex); return m_bytes; }
bool OrderCache::Contains(const uint256& quote_id) const { LOCK(m_mutex); return m_orders.count(quote_id) > 0; }

void OrderCache::EvictSpentBy(const CTransaction& tx)
{
    LOCK(m_mutex);
    for (const CTxIn& in : tx.vin) {
        auto bi = m_by_input.find(in.prevout);
        if (bi != m_by_input.end()) {
            // Copy the quote id out before erasing: EraseLocked() walks the
            // quote's inputs and erases m_by_input entries (including this one),
            // which would leave bi->second dangling if passed by reference.
            const uint256 quote_id = bi->second;
            EraseLocked(quote_id);
        }
    }
}

void OrderCache::TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t)
{
    if (tx.info.m_tx) EvictSpentBy(*tx.info.m_tx);
}

void OrderCache::BlockConnected(ChainstateRole, const std::shared_ptr<const CBlock>& block, const CBlockIndex*)
{
    if (!block) return;
    for (const CTransactionRef& tx : block->vtx) {
        if (tx) EvictSpentBy(*tx);
    }
}

} // namespace rfq
