// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AGGREGATION_POOL_H
#define BITCOIN_AGGREGATION_POOL_H

#include <primitives/transaction.h>
#include <sync.h>
#include <validationinterface.h>

#include <array>
#include <cstdint>
#include <map>
#include <vector>

namespace aggregation {

//! Target number of candidates a node keeps on hand for cover traffic.
static constexpr size_t POOL_TARGET = 20;
//! Hard cap on total candidates held, to bound memory.
static constexpr size_t POOL_MAX_TOTAL = 512;
//! Cap on candidates accepted from any single source peer.
static constexpr size_t POOL_MAX_PER_PEER = 8;
//! Max candidates merged into one aggregate (bounds aggregate size).
static constexpr size_t POOL_MAX_COMBINED = 16;
//! Number of lock shards (by input-outpoint hash top byte).
static constexpr size_t POOL_SHARDS = 16;

/**
 * Local pool of single-input-single-output fee-0 cover candidates received from
 * peers. Each candidate is keyed by its single input outpoint:
 *  - dedupe-on-insert: a second candidate spending an input already present is
 *    rejected (first-seen wins);
 *  - eviction: when any tx entering the mempool or a connected block spends a
 *    candidate's input, that candidate is dropped (it can no longer be combined).
 *
 * Sharded by outpoint hash so inserts/evictions on unrelated inputs do not
 * contend. No BLS/AEAD work happens under a shard lock.
 */
class CandidatePool : public CValidationInterface
{
public:
    CandidatePool() = default;

    //! Insert a validated candidate from `peer`. Returns false (no insert) if:
    //! the candidate is not 1-input, its input is already pooled, the per-peer
    //! cap is hit, or the global cap is hit.
    bool AddCandidate(const CTransactionRef& candidate, int64_t peer)
       ;

    //! Pick up to `max_n` candidates for an aggregate (oldest-first within
    //! shards is not guaranteed; selection is arbitrary but distinct inputs).
    std::vector<CTransactionRef> PickForAggregate(size_t max_n) const
       ;

    //! Drop the candidate holding `input`, if any. Returns true if one was removed.
    bool EvictByInput(const COutPoint& input);

    size_t Size() const;
    bool Contains(const COutPoint& input) const;

    // CValidationInterface: evict candidates whose input got spent.
    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t mempool_sequence) override
       ;
    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) override
       ;

private:
    struct Entry {
        CTransactionRef tx;
        int64_t peer;
    };

    static size_t ShardFor(const COutPoint& input);
    void EvictSpentBy(const CTransaction& tx);

    //! Shard i is guarded by m_shard_mutex[i]. (Clang thread-safety annotations
    //! cannot express a mutex array, so the pairing is enforced by convention.)
    mutable std::array<Mutex, POOL_SHARDS> m_shard_mutex;
    std::array<std::map<COutPoint, Entry>, POOL_SHARDS> m_shards;
    //! Per-peer counts, guarded by its own mutex (cross-shard).
    mutable Mutex m_peer_mutex;
    std::map<int64_t, size_t> m_per_peer GUARDED_BY(m_peer_mutex);
};

} // namespace aggregation

#endif // BITCOIN_AGGREGATION_POOL_H
