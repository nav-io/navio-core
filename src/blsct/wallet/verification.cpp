// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl.h>
#include <blsct/pos/pos.h>
#include <blsct/public_keys.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/range_proof/generators.h>
#include <blsct/wallet/verification.h>
#include <script/interpreter.h>
#include <script/script.h>

namespace blsct {

// BLSCT nSequence encoding (per-input absolute locktime commitment):
//
//   0xFFFFFFFF (SEQUENCE_FINAL) : no locktime constraint
//   Bit 31 set, != SEQUENCE_FINAL: reserved for future relative timelocks
//   0 .. LOCKTIME_THRESHOLD-1   : absolute height-based locktime
//                                 (spendable at block height >= nSequence)
//   LOCKTIME_THRESHOLD .. 0x7FFFFFFF : absolute time-based locktime (Unix ts)
//                                 (spendable when MTP >= nSequence)
//
// nSequence is part of CTxIn serialization and therefore covered by
// CTxIn::GetHash(), which BLSCT uses as the BLS sighash -- so the
// commitment is signature-bound and survives transaction aggregation.

static constexpr uint32_t BLSCT_SEQUENCE_RELATIVE_FLAG = (1U << 31); // 0x80000000

class BLSCTSignatureChecker : public TransactionSignatureChecker
{
    uint32_t m_input_locktime;

public:
    BLSCTSignatureChecker(const CTransaction* tx, unsigned int nIn)
        : TransactionSignatureChecker(tx, nIn, 0, MissingDataBehavior::FAIL),
          m_input_locktime(tx->vin[nIn].nSequence) {}

    bool CheckLockTime(const CScriptNum& nLockTime) const override
    {
        if (nLockTime < 0) return false;

        if (m_input_locktime == CTxIn::SEQUENCE_FINAL)
            return false;

        if (!(
            (m_input_locktime <  LOCKTIME_THRESHOLD && nLockTime <  LOCKTIME_THRESHOLD) ||
            (m_input_locktime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)))
            return false;

        return nLockTime <= static_cast<int64_t>(m_input_locktime);
    }
};

namespace {
// Shared RangeProofLogic/GeneratorsFactory. Both have guarded `inline static`
// init internally, but stack-allocating them per-call still pays mutex + field
// copy costs. One static instance per thread is cheap and thread-safe because
// the underlying tables are immutable after init.
//
// NOTE: we intentionally take addresses-of rather than references so callers
// that want to hoist use the same instances.
range_proof::GeneratorsFactory<Mcl>& GetSharedGenFactory()
{
    static range_proof::GeneratorsFactory<Mcl> gf;
    return gf;
}

bulletproofs_plus::RangeProofLogic<Mcl>& GetSharedRPLogic()
{
    static bulletproofs_plus::RangeProofLogic<Mcl> rp;
    return rp;
}

// Core verification body. Collects range proofs into `out_proofs` for deferred
// batch verification. If `verify_rp_inline` is true, the call also verifies
// the collected proofs before returning — this matches the legacy VerifyTx
// contract.
bool VerifyTxCore(const CTransaction& tx,
                  CCoinsViewCache& view,
                  TxValidationState& state,
                  std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>>& out_proofs,
                  const CAmount& blockReward,
                  const CAmount& minStake,
                  int nSpendHeight,
                  int64_t nMedianTimePast,
                  bool verify_rp_inline)
{
    if (!view.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-inputs-unknown");
    }

    auto& gf = GetSharedGenFactory();

    // Batched balance-key MSM. Every `gen.G * MclScalar(value)` contribution
    // is staged here; we invoke one scalar-mul per (distinct tokenId, sign)
    // by accumulating scalars that share the same generator.
    //
    // Points that are already committed (BLSCT coin commitments, staked
    // commitments, incoming `balanceKey` seeds) are added directly since they
    // are not scalar-mul results.
    struct GenAccum {
        MclG1Point G;
        MclScalar pos; // sum of positive scalars
        MclScalar neg; // sum of negative scalars
        bool has_pos{false};
        bool has_neg{false};
    };
    std::vector<GenAccum> gen_accums;
    gen_accums.reserve(tx.vout.size() + tx.vin.size() + 2);

    auto find_or_add_gen = [&](const TokenId& tid) -> GenAccum& {
        range_proof::Generators<Mcl> gen = gf.GetInstance(tid);
        for (auto& a : gen_accums) {
            if (a.G == gen.G) return a;
        }
        gen_accums.push_back({gen.G, MclScalar(0), MclScalar(0), false, false});
        return gen_accums.back();
    };

    MclG1Point balanceKey;

    if (blockReward > 0) {
        auto& a = find_or_add_gen(TokenId());
        a.pos = a.has_pos ? (a.pos + MclScalar(blockReward)) : MclScalar(blockReward);
        a.has_pos = true;
    }

    std::vector<Message> vMessages;
    std::vector<PublicKey> vPubKeys;

    if (!tx.IsCoinBase()) {
        for (const auto& in : tx.vin) {
            if (in.nSequence != CTxIn::SEQUENCE_FINAL) {
                if (in.nSequence & BLSCT_SEQUENCE_RELATIVE_FLAG)
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "reserved-sequence-bits");

                if (in.nSequence < LOCKTIME_THRESHOLD) {
                    if (static_cast<int64_t>(in.nSequence) > nSpendHeight)
                        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-final-input");
                } else {
                    if (static_cast<int64_t>(in.nSequence) > nMedianTimePast)
                        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-final-input");
                }
            }
        }

        size_t i = 0;
        for (auto& in : tx.vin) {
            Coin coin;

            if (!view.GetCoin(in.prevout, coin)) {
                return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-input-unknown");
            }

            BLSCTSignatureChecker checker(&tx, i++);
            ScriptError serror;
            uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

            if (!VerifyScript(in.scriptSig, coin.out.scriptPubKey, nullptr, flags, checker, &serror)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-script-check");
            }

            for (const auto& pair : checker.GetKeyMessagePairs()) {
                vPubKeys.emplace_back(pair.first);
                vMessages.emplace_back(pair.second.begin(), pair.second.end());
            }

            if (!coin.out.blsctData.spendingKey.IsZero()) {
                vPubKeys.emplace_back(coin.out.blsctData.spendingKey);
                auto in_hash = in.GetHash();
                vMessages.emplace_back(in_hash.begin(), in_hash.end());
            }

            if (coin.out.HasBLSCTRangeProof()) {
                // Input commitment already a point; fold directly.
                balanceKey = balanceKey + coin.out.blsctData.rangeProof.Vs[0];
            } else {
                auto& a = find_or_add_gen(coin.out.tokenId);
                a.pos = a.has_pos ? (a.pos + MclScalar(coin.out.nValue)) : MclScalar(coin.out.nValue);
                a.has_pos = true;
            }
        }
    }

    CAmount nFee = 0;
    bulletproofs_plus::RangeProofWithSeed<Mcl> stakedCommitmentRangeProof;

    for (auto& out : tx.vout) {
        auto out_hash = out.GetHash();
        blsct::ParsedPredicate parsedPredicate;

        if (out.predicate.size() > 0) {
            try {
                parsedPredicate = ParsePredicate(out.predicate);
            } catch (const std::ios_base::failure&) {
                // If predicate parsing fails, skip this output
                continue;
            }

            if (parsedPredicate.IsMintTokenPredicate()) {
                vPubKeys.emplace_back(parsedPredicate.GetPublicKey());
                vMessages.emplace_back(out_hash.begin(), out_hash.end());
                auto& a = find_or_add_gen(TokenId(parsedPredicate.GetPublicKey().GetHash()));
                a.pos = a.has_pos ? (a.pos + MclScalar(parsedPredicate.GetAmount())) : MclScalar(parsedPredicate.GetAmount());
                a.has_pos = true;
            } else if (parsedPredicate.IsCreateTokenPredicate()) {
                vPubKeys.emplace_back(parsedPredicate.GetPublicKey());
                vMessages.emplace_back(out_hash.begin(), out_hash.end());
            } else if (parsedPredicate.IsMintNftPredicate()) {
                vPubKeys.emplace_back(parsedPredicate.GetPublicKey());
                vMessages.emplace_back(out_hash.begin(), out_hash.end());
                auto& a = find_or_add_gen(TokenId(parsedPredicate.GetPublicKey().GetHash(), parsedPredicate.GetNftId()));
                a.pos = a.has_pos ? (a.pos + MclScalar(1)) : MclScalar(1);
                a.has_pos = true;
            } else if (out.scriptPubKey.IsFee() && parsedPredicate.IsPayFeePredicate()) {
                vMessages.emplace_back(blsct::Common::BLSCTFEE);
                vPubKeys.emplace_back(parsedPredicate.GetPublicKey());
            }

            if (!ExecutePredicate(parsedPredicate, view))
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-to-execute-predicate");
        }

        if (out.HasBLSCTKeys()) {
            vPubKeys.emplace_back(out.blsctData.ephemeralKey);
            vMessages.emplace_back(out_hash.begin(), out_hash.end());
        }

        if (out.HasBLSCTRangeProof()) {
            bulletproofs_plus::RangeProofWithSeed<Mcl> proof{out.blsctData.rangeProof, out.tokenId};
            out_proofs.emplace_back(proof);
            balanceKey = balanceKey - out.blsctData.rangeProof.Vs[0];

            if (out.GetStakedCommitmentRangeProof(stakedCommitmentRangeProof)) {
                stakedCommitmentRangeProof.Vs.Clear();
                stakedCommitmentRangeProof.Vs.Add(out.blsctData.rangeProof.Vs[0]);

                proof = bulletproofs_plus::RangeProofWithSeed<Mcl>{stakedCommitmentRangeProof, TokenId(), minStake};

                out_proofs.push_back(proof);
            }
        } else {
            if (out.nValue == 0) continue;
            if (parsedPredicate.IsPayFeePredicate()) {
                if (nFee > 0 || !MoneyRange(out.nValue)) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "more-than-one-fee-output");
                }
                nFee = out.nValue;
            }
            auto& a = find_or_add_gen(out.tokenId);
            a.neg = a.has_neg ? (a.neg + MclScalar(out.nValue)) : MclScalar(out.nValue);
            a.has_neg = true;
        }
    }

    // Fold all accumulated (G, scalar) pairs into balanceKey with one scalar
    // multiplication per distinct generator, instead of one per value.
    for (const auto& a : gen_accums) {
        if (a.has_pos) balanceKey = balanceKey + (a.G * a.pos);
        if (a.has_neg) balanceKey = balanceKey - (a.G * a.neg);
    }

    vMessages.emplace_back(blsct::Common::BLSCTBALANCE);
    vPubKeys.emplace_back(balanceKey);

    auto sigCheck = PublicKeys{vPubKeys}.VerifyBatch(vMessages, tx.txSig, true);

    if (!sigCheck)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-signature-check");

    if (verify_rp_inline) {
        auto& rp = GetSharedRPLogic();
        if (!rp.Verify(out_proofs)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-rangeproof-check");
        }
        out_proofs.clear(); // consumed
    }

    return true;
}
} // namespace

bool VerifyTx(const CTransaction& tx, CCoinsViewCache& view, TxValidationState& state, const CAmount& blockReward, const CAmount& minStake, int nSpendHeight, int64_t nMedianTimePast)
{
    std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>> proofs;
    return VerifyTxCore(tx, view, state, proofs, blockReward, minStake, nSpendHeight, nMedianTimePast, /*verify_rp_inline=*/true);
}

bool VerifyTxCollectProofs(const CTransaction& tx,
                           CCoinsViewCache& view,
                           TxValidationState& state,
                           std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>>& out_proofs,
                           const CAmount& blockReward,
                           const CAmount& minStake,
                           int nSpendHeight,
                           int64_t nMedianTimePast)
{
    return VerifyTxCore(tx, view, state, out_proofs, blockReward, minStake, nSpendHeight, nMedianTimePast, /*verify_rp_inline=*/false);
}

bool VerifyCollectedRangeProofs(const std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>>& proofs)
{
    if (proofs.empty()) return true;
    auto& rp = GetSharedRPLogic();
    return rp.Verify(proofs);
}
} // namespace blsct
