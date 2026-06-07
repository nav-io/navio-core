// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RFQ_ORDER_CACHE_H
#define BITCOIN_RFQ_ORDER_CACHE_H

#include <primitives/transaction.h>
#include <rfq/quote.h>
#include <rfq/request.h>
#include <sync.h>
#include <uint256.h>
#include <validationinterface.h>

#include <cstdint>
#include <list>
#include <map>
#include <vector>

namespace rfq {

//! Standing-order cache bound: 32 MiB of serialized quotes.
static constexpr size_t MAX_ORDER_CACHE_BYTES = 32u << 20;
//! Standing orders live at most 14 days regardless of their declared expiry.
static constexpr int64_t MAX_ORDER_TTL_SECONDS = 14 * 24 * 60 * 60;

/**
 * Bounded LRU cache of standing orders (broadcast pre-signed maker half-txs).
 * Any peer holding a matching order can answer an RFQ on behalf of an offline
 * maker. Entries are evicted when:
 *  - their effective expiry passes (min(declared expiry, 14 days from store)),
 *  - any input they spend appears in the mempool or a connected block,
 *  - the byte bound is exceeded (least-recently-used dropped first).
 *
 * Registered as a CValidationInterface for spent-input eviction, mirroring
 * aggregation::CandidatePool.
 */
class OrderCache : public CValidationInterface
{
public:
    explicit OrderCache(int64_t now);

    //! Store a standing order. Returns false if it has no half-tx, is already
    //! expired at `now`, or duplicates an existing quote_id. On success the
    //! effective expiry is min(order_expiry, now + 14 days).
    bool StoreOrder(const RfqQuote& q, int64_t now) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Return copies of all non-expired orders whose half-tx matches `req`'s
    //! token pair and size band. (Match semantics intentionally coarse here;
    //! the taker re-validates and ranks.) Touches LRU order.
    std::vector<RfqQuote> FindMatching(const RfqRequest& req, int64_t now)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Drop expired entries (effective expiry <= now). Returns count removed.
    size_t PruneExpired(int64_t now) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    size_t Bytes() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool Contains(const uint256& quote_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void BlockConnected(ChainstateRole, const std::shared_ptr<const CBlock>& block, const CBlockIndex*) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Entry {
        RfqQuote quote;
        int64_t effective_expiry;
        size_t bytes;
    };
    using ListIt = std::list<uint256>::iterator; // LRU: front = most recent

    void TouchLRU(const uint256& quote_id) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void EraseLocked(const uint256& quote_id) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void EvictToBound() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void EvictSpentBy(const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    mutable Mutex m_mutex;
    std::map<uint256, Entry> m_orders GUARDED_BY(m_mutex);
    std::list<uint256> m_lru GUARDED_BY(m_mutex); // front = most recent
    std::map<uint256, ListIt> m_lru_pos GUARDED_BY(m_mutex);
    //! input outpoint -> quote_id, for spent-input eviction.
    std::map<COutPoint, uint256> m_by_input GUARDED_BY(m_mutex);
    size_t m_bytes GUARDED_BY(m_mutex){0};
};

//! Process-global handle to the active order cache (wallet module reach).
void SetActiveOrderCache(OrderCache* cache);
OrderCache* GetActiveOrderCache();

} // namespace rfq

#endif // BITCOIN_RFQ_ORDER_CACHE_H
