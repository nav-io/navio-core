// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/pos/pos_check_queue.h>

#include <blsct/pos/proof.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <chain.h>

#include <cstdlib>

namespace blsct {

namespace {
// Batched PoS verification (SetMemProofProver::VerifyBatch) is opt-in while it
// is under review. Enable with NAVIO_BLSCT_POSBATCH=1. The batch path is
// correctness-equivalent to the per-item path (it always falls back to per-item
// verify to confirm a failure), so the flag only selects the fast path.
bool PoSBatchEnabled()
{
    static const bool enabled = [] {
        const char* v = std::getenv("NAVIO_BLSCT_POSBATCH");
        return v && v[0] == '1' && v[1] == '\0';
    }();
    return enabled;
}
} // namespace

bool PoSCheckItem::VerifyStandalone() const
{
    if (!proof) return false;
    auto res = proof->Verify(staked_commitments, eta_fiat_shamir, eta_phi, kernel_hash, next_target);
    return res == ProofOfStake::VALID;
}

void PoSCheckQueue::Push(PoSCheckItem&& item)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_items.emplace_back(std::move(item));
}

bool PoSCheckQueue::Flush(const CBlockIndex** failing)
{
    std::vector<PoSCheckItem> items;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        items.swap(m_items);
    }
    if (failing) *failing = nullptr;
    if (items.empty()) return true;

    // Fast path: random-linear-combination batch of the set-membership proofs
    // (one shared-generator MSM for the whole batch) plus per-item kernel range
    // proofs. If the batch rejects, fall through to per-item verify below: that
    // path is authoritative and pinpoints the offending block, so a (would-be
    // bug) batch false-negative cannot wrongly invalidate a valid chain.
    if (PoSBatchEnabled()) {
        std::vector<ProofOfStake::BatchItem> batch;
        batch.reserve(items.size());
        bool buildable = true;
        for (const auto& item : items) {
            if (!item.proof) { buildable = false; break; }
            batch.push_back({&item.staked_commitments, item.eta_fiat_shamir,
                             item.eta_phi, item.kernel_hash, item.next_target, item.proof});
        }
        if (buildable && ProofOfStake::VerifyBatch(batch)) return true;
        // else: fall through to the per-item pass.
    }

    // Per-item standalone verify. Also the failure-isolation path for the batch.
    for (const auto& item : items) {
        if (!item.VerifyStandalone()) {
            if (failing) *failing = item.pindex;
            return false;
        }
    }
    return true;
}

void PoSCheckQueue::Clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_items.clear();
}

size_t PoSCheckQueue::Size() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_items.size();
}

bool PoSCheckQueue::Empty() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_items.empty();
}

} // namespace blsct
