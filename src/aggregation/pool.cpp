// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <aggregation/pool.h>

#include <logging.h>

#include <blsct/wallet/verification.h>
#include <coins.h>
#include <consensus/params.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <kernel/mempool_entry.h>
#include <primitives/block.h>
#include <random.h>
#include <txmempool.h>

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

bool IsCandidateShape(const CTransaction& tx)
{
    if ((tx.nVersion & CTransaction::BLSCT_MARKER) == 0) return false;
    if (tx.vin.size() != 1) return false;
    if (tx.vout.size() != 1) return false;
    if (tx.vout[0].scriptPubKey.IsFee()) return false;
    if (GetTransactionWeight(tx) > CANDIDATE_MAX_WEIGHT) return false;
    return true;
}

bool CheckCandidate(const CTransaction& tx, CCoinsViewCache& view, const CTxMemPool* mempool,
                    int spend_height, int64_t median_time_past, const Consensus::Params& params,
                    TxValidationState& state)
{
    if (!CheckTransaction(tx, state)) return false;
    if (mempool != nullptr) {
        for (const CTxIn& in : tx.vin) {
            if (mempool->isSpent(in.prevout)) {
                return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-mempool-conflict");
            }
        }
    }
    CAmount fee{0};
    if (!Consensus::CheckTxInputs(tx, state, view, spend_height, fee)) return false;
    return blsct::VerifyTx(tx, view, state, /*blockReward=*/0, params.nPePoSMinStakeAmount,
                           spend_height, median_time_past, params.nBLSCTDefaultFee,
                           params.nBLSCTProofV2Height, /*threads=*/0,
                           blsct::VerifyTxOptions{.skip_fee_rule = true});
}

bool CandidatePool::WouldAccept(const CTransaction& candidate) const
{
    return IsCandidateShape(candidate) && !Contains(candidate.vin[0].prevout) && Size() < POOL_MAX_TOTAL;
}

bool CandidatePool::AddCandidate(const CTransactionRef& candidate, bool reward_input)
{
    // Candidates arrive unauthenticated from the network. Network ingress runs
    // CheckCandidate (signature, UTXO, maturity, mempool conflict) before this;
    // the shape is checked again here because the debug RPC
    // addaggregationcandidate inserts directly.
    if (candidate == nullptr || !IsCandidateShape(*candidate)) return false;
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
    const size_t want_other = max_n - out.size();
    const size_t take_other = std::min(want_other, other.size());
    if (take_other < want_other) {
        // The mirror case: an initiator spending mostly transfers against a
        // reward-heavy pool gets reward-backed top-ups instead.
        LogPrint(BCLog::NET, "p2pmsg: type-aware cover pick short on transfer-backed candidates (wanted %u, pool has %u)\n", (unsigned)want_other, (unsigned)other.size());
    }
    out.insert(out.end(), other.begin(), other.begin() + take_other);
    if (out.size() < max_n && take_reward < reward.size()) {
        const size_t top_up = std::min(max_n - out.size(), reward.size() - take_reward);
        out.insert(out.end(), reward.begin() + take_reward, reward.begin() + take_reward + top_up);
    }
    return out;
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
