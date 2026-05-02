// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/pos/pos_check_queue.h>

#include <blsct/pos/proof.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <chain.h>

namespace blsct {

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

    // TODO(#3): replace this loop with:
    //   (1) SetMemProofProver<Mcl>::VerifyBatch(setup, batch_items)  — needs
    //       random-linear-combination batching across each proof's pairing
    //       equation. Requires crypto review.
    //   (2) bulletproofs_plus::RangeProofLogic<Mcl>::Verify(vector) over
    //       every item's range proof — already batches via internal std::async.
    //
    // Until VerifyBatch lands, fallback: per-item standalone verify. This is
    // correctness-preserving but gives no crypto-batch speedup; the
    // cross-block pipelining via PoSCheckQueue alone buys only thread-
    // amortisation wins (~0.5-1 ms/block).
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
