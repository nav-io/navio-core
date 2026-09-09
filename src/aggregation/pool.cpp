// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <aggregation/pool.h>

#include <logging.h>

#include <consensus/validation.h>
#include <kernel/mempool_entry.h>
#include <primitives/block.h>
#include <random.h>

#include <algorithm>
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
    return m_shards[s].contains(input);
}

bool CandidatePool::AddCandidate(const CTransactionRef& candidate, bool reward_input)
{
    if (candidate == nullptr) return false;
    // Structural validation. Candidates arrive unauthenticated from the network
    // and are combined WITHOUT a per-candidate signature/UTXO recheck, so a
    // malformed one would only fail when the whole aggregate is built --
    // wasting the initiator's attempt. Reject the obviously-invalid shapes here:
    //  - a BLSCT tx (marker set),
    //  - exactly one input and one output (a 1-in/1-out self-spend),
    //  - NOT a fee output (candidates must be fee-0 and fee-output-free; a fee
    //    output would give the combined tx a second fee output and fail
    //    consensus's one-fee-output rule),
    //  - within a sane weight bound (oversized candidates inflate the
    //    initiator's additionalFee and memory use).
    if ((candidate->nVersion & CTransaction::BLSCT_MARKER) == 0) return false;
    if (candidate->vin.size() != 1) return false;
    if (candidate->vout.size() != 1) return false;
    if (candidate->vout[0].scriptPubKey.IsFee()) return false;
    if (GetTransactionWeight(*candidate) > CANDIDATE_MAX_WEIGHT) return false;
    const COutPoint& input = candidate->vin[0].prevout;

    // Total cap only (best-effort; Size() is a snapshot). There is deliberately
    // NO per-peer cap: `peer` is the delivering neighbour (pfrom.GetId()), which
    // Dandelion stem routing and ephemeral reply keys make non-identifying, so a
    // per-peer cap bounds neither the originating server nor an injecting
    // attacker -- it only imposed a false ceiling that a single honest server
    // routinely exceeded. Pool abuse is bounded instead by POOL_MAX_TOTAL,
    // input-outpoint dedupe, and evict-on-failure at aggregate time.
    if (Size() >= POOL_MAX_TOTAL) return false;

    const size_t s = ShardFor(input);
    bool inserted = false;
    {
        LOCK(m_shard_mutex[s]);
        inserted = m_shards[s].emplace(input, Entry{candidate, reward_input}).second;
    }
    return inserted;
}

std::vector<CTransactionRef> CandidatePool::PickForAggregate(size_t max_n) const
{
    if (max_n > POOL_MAX_COMBINED) max_n = POOL_MAX_COMBINED;

    // Gather all candidates, then pick a RANDOM subset. A deterministic scan
    // (shards 0..15, each map in outpoint order) always returns the same
    // candidates, so a single poison candidate that makes an aggregate fail
    // would be re-selected on every attempt -- a permanent DoS. Randomizing
    // means a failed candidate is unlikely to be re-picked, and (with
    // evict-on-failure at the call site) the pool self-heals.
    std::vector<CTransactionRef> all;
    for (size_t i = 0; i < POOL_SHARDS; ++i) {
        LOCK(m_shard_mutex[i]);
        for (const auto& [outpoint, entry] : m_shards[i]) all.push_back(entry.tx);
    }
    if (all.size() <= max_n) return all;

    FastRandomContext rng;
    std::shuffle(all.begin(), all.end(), rng);
    all.resize(max_n);
    return all;
}

std::vector<CTransactionRef> CandidatePool::PickForAggregate(size_t max_n, size_t prefer_reward) const
{
    if (max_n > POOL_MAX_COMBINED) max_n = POOL_MAX_COMBINED;
    if (prefer_reward > max_n) prefer_reward = max_n;

    std::vector<CTransactionRef> reward, other;
    for (size_t i = 0; i < POOL_SHARDS; ++i) {
        LOCK(m_shard_mutex[i]);
        for (const auto& [outpoint, entry] : m_shards[i]) {
            (entry.reward_input ? reward : other).push_back(entry.tx);
        }
    }
    FastRandomContext rng;
    std::shuffle(reward.begin(), reward.end(), rng);
    std::shuffle(other.begin(), other.end(), rng);

    // Fill the preferred type quota first, the complementary type next, then
    // top up from whatever remains: a type-mismatched cover still beats
    // returning fewer covers than asked for.
    std::vector<CTransactionRef> out;
    const size_t take_reward = std::min(prefer_reward, reward.size());
    if (take_reward < prefer_reward) {
        // This selection is a privacy mitigation, and a silent shortfall
        // no-ops it exactly in its motivating case (initiator spending mostly
        // reward outputs against a transfer-heavy pool). Make that visible.
        LogPrint(BCLog::NET, "p2pmsg: type-aware cover pick short on reward-backed candidates (wanted %u, pool has %u)\n", (unsigned)prefer_reward, (unsigned)reward.size());
    }
    out.insert(out.end(), reward.begin(), reward.begin() + take_reward);
    const size_t take_other = std::min(max_n - out.size(), other.size());
    out.insert(out.end(), other.begin(), other.begin() + take_other);
    if (out.size() < max_n && take_reward < reward.size()) {
        const size_t top_up = std::min(max_n - out.size(), reward.size() - take_reward);
        out.insert(out.end(), reward.begin() + take_reward, reward.begin() + take_reward + top_up);
    }
    return out;
}

void CandidatePool::MarkRewardInput(const COutPoint& input)
{
    const size_t s = ShardFor(input);
    LOCK(m_shard_mutex[s]);
    auto it = m_shards[s].find(input);
    if (it != m_shards[s].end()) it->second.reward_input = true;
}

bool CandidatePool::EvictByInput(const COutPoint& input)
{
    const size_t s = ShardFor(input);
    LOCK(m_shard_mutex[s]);
    return m_shards[s].erase(input) > 0;
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
