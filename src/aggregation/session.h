// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AGGREGATION_SESSION_H
#define BITCOIN_AGGREGATION_SESSION_H

#include <aggregation/pool.h>
#include <blsct/wallet/txfactory_global.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <util/overflow.h>

#include <algorithm>
#include <span>
#include <vector>

namespace aggregation {

//! Default for -aggregatesends: every wallet BLSCT send is merged with fee-0
//! cover candidates from the node's pool when any are available (falling back
//! to a plain send when none are, or when the merge fails).
static constexpr bool DEFAULT_AGGREGATE_SENDS{true};

//! Cover-ratio policy: one cover candidate per this many own-half inputs.
//! Cover is measured in INPUTS, not candidates -- an aggregate spending 25
//! own inputs with 4 covers attributes the bulk to one wallet under a count
//! heuristic. The target derived from this ratio is a floor the initiator
//! tries to reach (pulling on demand and waiting -aggregatecoverwait), never
//! a cap, and never a reason to fail a send.
static constexpr size_t COVER_INPUT_RATIO = 4;
//! Only sends with at least this many own inputs wait for cover: small sends
//! already blend into small aggregates, and stalling every 2-input send when
//! the pool is empty would be all cost and no benefit.
static constexpr size_t COVER_WAIT_MIN_INPUTS = 8;
//! Default for -aggregatecoverwait (seconds).
static constexpr int64_t DEFAULT_COVER_WAIT_SECONDS = 10;

//! The cover-candidate floor for an own half with `own_inputs` inputs.
inline size_t TargetCoverCount(size_t own_inputs)
{
    const size_t target = (own_inputs + COVER_INPUT_RATIO - 1) / COVER_INPUT_RATIO;
    return std::min(target, POOL_MAX_COMBINED);
}

//! Per-byte weight of a 1-in-1-out fee-0 BLSCT candidate, used to size the
//! initiator's over-funded fee. Measured empirically; refined by bench. A
//! conservative over-estimate only costs the initiator a little extra fee.
static constexpr int64_t CANDIDATE_WEIGHT_ESTIMATE = 2500;

//! Serialized-weight overhead a standalone BLSCT tx carries that a COMBINED
//! aggregate does NOT duplicate per half: the version marker, the lock time,
//! the empty in/out count varints, and -- the large part -- the ~96-byte BLS
//! txSig. CombineHalves aggregates every half's txSig into a single signature
//! and keeps one version/locktime, so each merged candidate contributes only
//! its input+output body to the aggregate, not this fixed per-tx overhead.
inline int64_t EmptyBlsctTxOverhead()
{
    // A default CMutableTransaction already carries a txSig member, which the
    // serializer emits once the BLSCT marker is set -- so the empty tx's weight
    // captures the full per-tx overhead (marker + counts + locktime + txSig).
    CMutableTransaction empty;
    empty.nVersion |= CTransaction::BLSCT_MARKER;
    return blsct::GetTransactionWeight(CTransaction(empty));
}

//! Sum the INCREMENTAL weight a set of candidate half-txs adds to a combined
//! aggregate: each candidate's standalone weight minus the per-tx overhead
//! (EmptyBlsctTxOverhead) that combining removes. Using the standalone weight
//! instead would over-fund the initiator's fee by ~overhead per candidate --
//! and that surplus is observable on-chain (fee/rate minus the aggregate's
//! actual weight), leaking the cover-half count the single fee output is meant
//! to hide. Charging the incremental weight makes the aggregate's fee equal
//! its true size * rate, so an aggregated send is fee-indistinguishable from a
//! plain send of the same final size.
inline int64_t SumCandidateWeight(std::span<const CTransactionRef> candidates)
{
    const int64_t overhead = EmptyBlsctTxOverhead();
    int64_t w = 0;
    for (const auto& c : candidates) {
        if (c) {
            const int64_t incremental = blsct::GetTransactionWeight(*c) - overhead;
            w += incremental > 0 ? incremental : 0;
        }
    }
    return w;
}

inline int64_t SumCandidateWeight(const std::vector<CTransactionRef>& candidates)
{
    return SumCandidateWeight(std::span<const CTransactionRef>{candidates.data(), candidates.size()});
}

//! The additional fee an initiator must add to its own half so the combined
//! transaction (own half + these fee-0 candidates) clears the consensus
//! minimum fee for the COMBINED weight. = sum(candidate weights) * fee_rate.
inline CAmount RequiredCandidateFee(std::span<const CTransactionRef> candidates, CAmount fee_rate)
{
    // weight and fee_rate are both bounded in practice (POOL_MAX_COMBINED
    // candidates, a policy fee rate), but candidate weight is influenced by
    // network-supplied tx sizes, so guard the product against int64 overflow
    // rather than silently wrapping to a negative/under-funded fee.
    const int64_t weight = SumCandidateWeight(candidates);
    if (weight < 0 || fee_rate < 0) return MAX_MONEY;
    // Portable overflow check (no __builtin/__int128; MSVC + 32-bit safe). An
    // out-of-range product is clamped; the caller treats it as a hard failure.
    return CheckedMul<CAmount>(weight, fee_rate).value_or(MAX_MONEY);
}

inline CAmount RequiredCandidateFee(const std::vector<CTransactionRef>& candidates, CAmount fee_rate)
{
    return RequiredCandidateFee(std::span<const CTransactionRef>{candidates.data(), candidates.size()}, fee_rate);
}

} // namespace aggregation

#endif // BITCOIN_AGGREGATION_SESSION_H
