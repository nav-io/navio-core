// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AGGREGATION_COMBINE_H
#define BITCOIN_AGGREGATION_COMBINE_H

#include <primitives/transaction.h>

#include <optional>
#include <span>

namespace aggregation {

//! Combine several BLSCT half-transactions into one aggregate.
//!
//! Each half already carries `tx.txSig` = the BLS aggregate of all of that
//! party's signatures (input sigs + balance sig over its own gamma + fee sig).
//! Because BLS signature aggregation is associative, the combined transaction is
//! valid when its `txSig` is the aggregate of every half's `txSig` over the
//! union of all inputs and outputs. No party shares or recomputes another's
//! gamma; no re-signing happens here. This mirrors navcoin-core's
//! CombineBLSCTTransactions.
//!
//! Preconditions the caller must uphold for the result to verify:
//!  - every half is a BLSCT tx (`BLSCT_MARKER` set),
//!  - inputs are disjoint across halves (no double-spend),
//!  - at most one half contributes a non-zero-value fee output (candidates are
//!    fee-0; the initiator's half carries the whole fee). Zero-value fee outputs
//!    are allowed on every half and are preserved so their predicate signatures
//!    remain covered by the aggregate `txSig`.
//!
//! Returns std::nullopt if `halves` is empty or any input is duplicated across
//! halves (a programming/peer error the caller should treat as invalid).
std::optional<CMutableTransaction> CombineHalves(std::span<const CTransactionRef> halves);

} // namespace aggregation

#endif // BITCOIN_AGGREGATION_COMBINE_H
