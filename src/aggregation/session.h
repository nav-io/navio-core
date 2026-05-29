// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AGGREGATION_SESSION_H
#define BITCOIN_AGGREGATION_SESSION_H

#include <consensus/amount.h>
#include <primitives/transaction.h>

#include <optional>
#include <span>
#include <vector>

namespace aggregation {

//! Per-byte weight of a 1-in-1-out fee-0 BLSCT candidate, used to size the
//! initiator's over-funded fee. Measured empirically; refined by bench. A
//! conservative over-estimate only costs the initiator a little extra fee.
static constexpr int64_t CANDIDATE_WEIGHT_ESTIMATE = 2500;

//! Sum the BLSCT transaction weight of a set of candidate half-txs.
int64_t SumCandidateWeight(std::span<const CTransactionRef> candidates);

//! The additional fee an initiator must add to its own half so the combined
//! transaction (own half + these fee-0 candidates) clears the consensus
//! minimum fee for the COMBINED weight. = sum(candidate weights) * fee_rate.
CAmount RequiredCandidateFee(std::span<const CTransactionRef> candidates, CAmount fee_rate);

} // namespace aggregation

#endif // BITCOIN_AGGREGATION_SESSION_H
