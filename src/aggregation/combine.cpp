// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <aggregation/combine.h>

#include <blsct/signature.h>

#include <set>
#include <vector>

namespace aggregation {

std::optional<CMutableTransaction> CombineHalves(std::span<const CTransactionRef> halves)
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

        // Preserve the union of inputs; reject cross-half double-spends.
        for (const CTxIn& in : tx.vin) {
            if (!seen_inputs.insert(in.prevout).second) {
                return std::nullopt; // duplicate input across halves
            }
            out.vin.push_back(in);
        }

        // Preserve every output verbatim, including zero-value fee outputs so
        // their PayFee predicate signatures stay covered by the aggregate sig.
        for (const CTxOut& o : tx.vout) {
            out.vout.push_back(o);
        }

        sigs.push_back(tx.txSig);
    }

    out.txSig = blsct::Signature::Aggregate(sigs);
    return out;
}

} // namespace aggregation
