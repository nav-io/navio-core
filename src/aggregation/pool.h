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
//! Max candidates merged into one aggregate (bounds aggregate size).
static constexpr size_t POOL_MAX_COMBINED = 16;
//! Upper bound on a single candidate's serialized weight. A candidate is a
//! 1-input/1-output BLSCT self-spend (~2.5k weight); anything materially larger
//! is malformed or a griefing attempt (it would inflate the initiator's
//! additionalFee, since RequiredCandidateFee sums candidate weights). Rejected
//! at ingest so it can neither bloat memory nor the fee.
static constexpr int64_t CANDIDATE_MAX_WEIGHT = 6000;
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
class CandidatePool final : public CValidationInterface
{
public:
    CandidatePool() = default;

    //! Insert a validated candidate from `peer`. Returns false (no insert) if:
    //! the candidate is not 1-input, its input is already pooled, the per-peer
    //! cap is hit, or the global cap is hit. `reward_input` records whether the
    //! candidate's prev-out was created by a coinbase (block-reward) tx -- that
    //! is public chain data, and matching it against the initiator's own input
    //! types is what makes the cover blend (see PickForAggregate).
    bool AddCandidate(const CTransactionRef& candidate, bool reward_input = false)
       ;

    //! Pick up to `max_n` candidates for an aggregate (random subset so a
    //! poison candidate is not re-picked forever; distinct inputs).
    std::vector<CTransactionRef> PickForAggregate(size_t max_n) const
       ;

    //! Type-aware pick: up to `max_n` candidates, preferring `prefer_reward`
    //! of them to be backed by coinbase (block-reward) prev-outs and the rest
    //! by ordinary transfers. Whether a prev-out was a block reward is PUBLIC
    //! chain data, so covers whose input type does not match the initiator's
    //! own inputs partition cleanly away from them under a type heuristic --
    //! an aggregate spending 25 reward outputs plus 4 transfer-backed covers
    //! protects nothing. Falls back across types when one side runs short:
    //! mismatched cover still beats fewer covers. Random within each type
    //! class for the same poison-resistance as the untyped overload.
    //!
    //! Trade-off, stated rather than silent: unlike the untyped pick, the
    //! result is no longer independent of the initiator's own half -- an
    //! observer who seeded the pool with candidates it can recognise on
    //! chain reads prefer_reward (= ceil(k*r/n)) from the picked mix, and
    //! r == 0 is a one-shot deterministic distinguisher. Much of r is
    //! already inferable from the public input types, so the marginal leak
    //! is bounded, but the independence property is deliberately spent here
    //! to buy type blending.
    std::vector<CTransactionRef> PickForAggregate(size_t max_n, size_t prefer_reward) const
       ;

    //! Flag the pooled candidate holding `input` as reward-backed. Split from
    //! AddCandidate so the (cs_main-holding) chainstate classification runs
    //! only for candidates that actually entered the pool -- a message
    //! rejected by the structural checks or the caps must not pay for a coin
    //! lookup, grow the tip coins cache, or block a p2pmsg worker. No-op if
    //! the entry is gone (already evicted).
    void MarkRewardInput(const COutPoint& input);

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
        //! Prev-out was a coinbase (block-reward) output. One-shot snapshot
        //! taken at pool admission: a prev-out whose block is not yet
        //! connected classifies as transfer permanently (no re-check).
        bool reward_input{false};
    };

    static size_t ShardFor(const COutPoint& input);
    void EvictSpentBy(const CTransaction& tx);

    //! Shard i is guarded by m_shard_mutex[i]. (Clang thread-safety annotations
    //! cannot express a mutex array, so the pairing is enforced by convention.)
    mutable std::array<Mutex, POOL_SHARDS> m_shard_mutex;
    std::array<std::map<COutPoint, Entry>, POOL_SHARDS> m_shards;
};

//! Process-global handle to the active candidate pool (set at init, cleared at
//! shutdown). Lets the wallet module reach it, since a wallet RPC's context is a
//! WalletContext rather than a NodeContext. nullptr when -p2pmsg is disabled.
void SetActivePool(CandidatePool* pool);
CandidatePool* GetActivePool();

} // namespace aggregation

#endif // BITCOIN_AGGREGATION_POOL_H
