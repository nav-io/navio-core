// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLSCT_VERIFICATION_H
#define BLSCT_VERIFICATION_H

#include <blsct/arith/mcl/mcl.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/tokens/predicate_exec.h>
#include <chain.h>
#include <coins.h>
#include <consensus/validation.h>

#include <vector>

namespace blsct {
bool VerifyTx(const CTransaction& tx, CCoinsViewCache& view, TxValidationState& state, const CAmount& blockReward = 0, const CAmount& minStake = 0, int nSpendHeight = 0, int64_t nMedianTimePast = 0);

// Same semantics as VerifyTx, but defers the final bulletproofs++ batch check
// to the caller. On success, appends the tx's range proofs to `out_proofs` so
// the caller can invoke `RangeProofLogic::Verify` once per block over the
// aggregated set. All other checks (script, signatures, predicate) run inline.
bool VerifyTxCollectProofs(const CTransaction& tx,
                           CCoinsViewCache& view,
                           TxValidationState& state,
                           std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>>& out_proofs,
                           const CAmount& blockReward = 0,
                           const CAmount& minStake = 0,
                           int nSpendHeight = 0,
                           int64_t nMedianTimePast = 0);

// Batch verify collected range proofs. Call once per block after all
// VerifyTxCollectProofs calls succeed.
bool VerifyCollectedRangeProofs(const std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>>& proofs);
}
#endif // BLSCT_VERIFICATION_H
