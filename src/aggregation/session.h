// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AGGREGATION_SESSION_H
#define BITCOIN_AGGREGATION_SESSION_H

#include <blsct/wallet/txfactory_global.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>

#include <span>
#include <vector>

namespace aggregation {

//! Per-byte weight of a 1-in-1-out fee-0 BLSCT candidate, used to size the
//! initiator's over-funded fee. Measured empirically; refined by bench. A
//! conservative over-estimate only costs the initiator a little extra fee.
static constexpr int64_t CANDIDATE_WEIGHT_ESTIMATE = 2500;

//! Sum the BLSCT transaction weight of a set of candidate half-txs.
inline int64_t SumCandidateWeight(std::span<const CTransactionRef> candidates)
{
    int64_t w = 0;
    for (const auto& c : candidates) {
        if (c) w += blsct::GetTransactionWeight(*c);
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
    CAmount fee;
    if (weight < 0 || fee_rate < 0 || __builtin_mul_overflow(weight, fee_rate, &fee)) {
        return MAX_MONEY; // clamp: caller treats an out-of-range fee as a hard failure
    }
    return fee;
}

inline CAmount RequiredCandidateFee(const std::vector<CTransactionRef>& candidates, CAmount fee_rate)
{
    return RequiredCandidateFee(std::span<const CTransactionRef>{candidates.data(), candidates.size()}, fee_rate);
}

} // namespace aggregation

#endif // BITCOIN_AGGREGATION_SESSION_H
