// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_POS_POS_CHECK_QUEUE_H
#define NAVIO_BLSCT_POS_POS_CHECK_QUEUE_H

#include <blsct/arith/blst/blst.h>
#include <blsct/arith/blst/blst_g1point.h>
#include <blsct/pos/proof.h>
#include <primitives/block.h>
#include <uint256.h>

#include <mutex>
#include <vector>

class CBlockIndex;

namespace blsct {

// A snapshot of all inputs needed to verify one block's PoS proof. Captured
// by value at ConnectBlock time so the tx-verify loop and subsequent block
// processing cannot invalidate the data underneath an in-flight verification.
struct PoSCheckItem {
    const CBlockIndex* pindex{nullptr};
    Elements<Blst::Point> staked_commitments;
    Blst::Scalar eta_fiat_shamir;
    Message eta_phi;
    uint256 kernel_hash;
    unsigned int next_target{0};
    const ProofOfStake* proof{nullptr};   // Must outlive the queue entry. The
                                          // owning CBlock stays alive across
                                          // ConnectBlock; the queue must be
                                          // drained before the block is freed.

    // Run the per-item verification synchronously. Used as the failure-
    // isolation fallback when a batched Verify cannot pinpoint which item
    // broke the batch.
    bool VerifyStandalone() const;
};

// Deferred-verify queue for PoS proofs. Collects one PoSCheckItem per block
// during an ActivateBestChainStep run, then drains them all at the end with
// a batched verify.
//
// PERFORMANCE GOAL (pending crypto work): implement
//   SetMemProofProver<Blst>::VerifyBatch(vector<...>)
// so that N proofs can be verified in a single random-linear-combination
// multiexp + pairing check. Combined with the already-batchable
// bulletproofs_plus::RangeProofLogic::Verify(vector<...>), this reduces
// per-block PoS verify cost from ~9-11 ms to ~5-7 ms amortised.
//
// ROLLBACK CONTRACT: if the batched Flush() returns false, the first failing
// pindex is identified by per-item fallback (VerifyStandalone). The caller
// (ActivateBestChainStep) must then InvalidateBlock() that pindex and rewind
// the tip to the last-good block via the existing DisconnectTip path.
class PoSCheckQueue {
public:
    void Push(PoSCheckItem&& item);

    // Returns true iff every queued proof verifies. On failure, `failing`
    // receives the first offending CBlockIndex (may be nullptr if not
    // identifiable). Clears the queue in both cases.
    bool Flush(const CBlockIndex** failing = nullptr);

    void Clear();
    size_t Size() const;
    bool Empty() const;

private:
    mutable std::mutex m_mutex;
    std::vector<PoSCheckItem> m_items;
};

} // namespace blsct

#endif // NAVIO_BLSCT_POS_POS_CHECK_QUEUE_H
