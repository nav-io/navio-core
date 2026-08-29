// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AGGREGATION_COMBINE_H
#define BITCOIN_AGGREGATION_COMBINE_H

#include <blsct/arith/blst/blst.h>
#include <blsct/signature.h>
#include <primitives/transaction.h>

#include <algorithm>
#include <random>
#include <set>
#include <optional>
#include <span>
#include <vector>

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
//!  - at most one half contributes a fee output at all. Candidate halves are
//!    built with NO fee output (BuildTx `emitFeeOutput=false`), so only the
//!    initiator's half carries one and the combined tx has exactly one fee
//!    output. This is what keeps the aggregate from leaking its party count:
//!    a per-half fee output would delimit each party's output run.
//!
//! The combined inputs and outputs are shuffled so their on-chain order does
//! not reveal which half contributed them. The BLSCT aggregate signature and
//! balance proof are order-independent, so reordering does not affect validity
//! (mirrors the shuffle `TxFactoryBase::BuildTx` applies to a single tx).
//!
//! Returns std::nullopt if `halves` is empty or any input is duplicated across
//! halves (a programming/peer error the caller should treat as invalid).
inline std::optional<CMutableTransaction> CombineHalves(std::span<const CTransactionRef> halves)
{
    if (halves.empty()) return std::nullopt;

    CMutableTransaction out;
    out.nVersion = CTransaction::BLSCT_MARKER;

    std::set<COutPoint> seen_inputs;
    std::vector<blsct::Signature> sigs;
    sigs.reserve(halves.size());

    for (const auto& ref : halves) {
        if (ref == nullptr) return std::nullopt;
        const CTransaction& tx = *ref;

        for (const CTxIn& in : tx.vin) {
            if (!seen_inputs.insert(in.prevout).second) return std::nullopt;
            out.vin.push_back(in);
        }
        for (const CTxOut& o : tx.vout) {
            out.vout.push_back(o);
        }
        sigs.push_back(tx.txSig);
    }

    out.txSig = blsct::Signature::Aggregate(sigs);

    // Shuffle inputs and outputs so the aggregate does not expose the per-half
    // grouping (which inputs/outputs belong to the same party). Seed from
    // BLSCT's secure randomness (BlstScalar::Rand), matching BuildTx, so the
    // aggregation lib does not need FastRandomContext.
    std::seed_seq seed{BlstScalar::Rand().GetUint64(), BlstScalar::Rand().GetUint64(),
                       BlstScalar::Rand().GetUint64(), BlstScalar::Rand().GetUint64()};
    std::mt19937_64 rng(seed);
    std::shuffle(out.vin.begin(), out.vin.end(), rng);
    std::shuffle(out.vout.begin(), out.vout.end(), rng);

    return out;
}

inline std::optional<CMutableTransaction> CombineHalves(const std::vector<CTransactionRef>& halves)
{
    return CombineHalves(std::span<const CTransactionRef>{halves.data(), halves.size()});
}

} // namespace aggregation

#endif // BITCOIN_AGGREGATION_COMBINE_H
