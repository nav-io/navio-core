// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLSCT_VERIFICATION_H
#define BLSCT_VERIFICATION_H

#include <blsct/arith/mcl/mcl.h>
#include <blsct/public_key.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/tokens/predicate_exec.h>
#include <blsct/wallet/txfactory_global.h>
#include <chain.h>
#include <coins.h>
#include <consensus/validation.h>

#include <chrono>
#include <string>
#include <vector>

namespace blsct {
struct PreparedTxSignatureCheck {
    uint256 txid;
    Signature tx_sig;
    std::vector<PublicKey> pubkeys;
    std::vector<PublicKey::Message> messages;
    size_t vin_count{0};
    size_t vout_count{0};
    size_t total_pairs{0};
    size_t pairs_from_inputs{0};
    size_t pairs_from_outputs{0};
    std::chrono::microseconds init{};
    std::chrono::microseconds inputs{};
    std::chrono::microseconds outputs{};
};

struct TxSignatureBatchResult {
    bool ok{true};
    uint256 failed_txid{};
    std::string failure_reason;
    std::chrono::microseconds total{};
};

// NOTE: nSpendHeight = 0 / nMedianTimePast = 0 silently reject any input whose
// nSequence encodes a locktime > 0 (height-based) or MTP > 0 (time-based).
// Callers that do not have a real chain context (e.g. unit tests that only
// create SEQUENCE_FINAL transactions) may safely pass the defaults.
// Block-validation callers MUST pass real values.
//
// `nBLSCTDefaultFee` is the per-byte fee floor (sat / serialized byte) used
// to enforce the minimum-fee consensus rule
//     nFee >= blsct::GetTransactionWeight(tx) * nBLSCTDefaultFee
// on every non-coinbase BLSCT transaction. Block-validation callers MUST
// pass `Consensus::Params::nBLSCTDefaultFee`; tests/helpers may rely on the
// default (== `BLSCT_DEFAULT_FEE`).
bool VerifyTx(const CTransaction& tx, CCoinsViewCache& view, TxValidationState& state, const CAmount& blockReward = 0, const CAmount& minStake = 0, int nSpendHeight = 0, int64_t nMedianTimePast = 0, const CAmount& nBLSCTDefaultFee = BLSCT_DEFAULT_FEE);

// Same collection semantics as VerifyTxCollectProofs, but also returns the
// prepared aggregate-signature job so callers can defer BLS signature checking
// and overlap it with block-wide rangeproof verification.
bool PrepareTxForDeferredVerification(const CTransaction& tx,
                                      CCoinsViewCache& view,
                                      TxValidationState& state,
                                      std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>>& out_proofs,
                                      PreparedTxSignatureCheck& out_sig_check,
                                      const CAmount& blockReward,
                                      const CAmount& minStake,
                                      int nSpendHeight,
                                      int64_t nMedianTimePast,
                                      const CAmount& nBLSCTDefaultFee = BLSCT_DEFAULT_FEE);

// Same semantics as VerifyTx, but defers the final bulletproofs++ batch check
// to the caller. On success, appends the tx's range proofs to `out_proofs` so
// the caller can invoke `RangeProofLogic::Verify` once per block over the
// aggregated set. All other checks (script, signatures, predicate) run inline.
// Block-validation callers MUST pass the real chain height and median-time-past
// so that sequence-based locktime checks activate correctly.
bool VerifyTxCollectProofs(const CTransaction& tx,
                           CCoinsViewCache& view,
                           TxValidationState& state,
                           std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>>& out_proofs,
                           const CAmount& blockReward,
                           const CAmount& minStake,
                           int nSpendHeight,
                           int64_t nMedianTimePast,
                           const CAmount& nBLSCTDefaultFee = BLSCT_DEFAULT_FEE);

// Batch verify prepared aggregate-signature jobs collected by
// PrepareTxForDeferredVerification.
TxSignatureBatchResult VerifyPreparedTxSignatures(const std::vector<PreparedTxSignatureCheck>& sig_checks);

// Batch verify collected range proofs. Call once per block after all
// VerifyTxCollectProofs calls succeed.
bool VerifyCollectedRangeProofs(const std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>>& proofs);
}
#endif // BLSCT_VERIFICATION_H
