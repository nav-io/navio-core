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
#include <logging.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <util/time.h>

#include <chrono>


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
    using Clock = std::chrono::steady_clock;
    const bool bench_on = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
    const auto t_begin = Clock::now();

    if (!view.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-inputs-unknown");
    }

    auto& gf = GetSharedGenFactory();

    MclG1Point balanceKey;

    if (blockReward > 0) {
        range_proof::Generators<Mcl> gen = gf.GetInstance(TokenId());
        balanceKey = (gen.G * MclScalar(blockReward));
    }

    std::vector<Message> vMessages;
    std::vector<PublicKey> vPubKeys;
    auto t_init = Clock::now();

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

        // Prefetch all spent coins serially. CCoinsViewCache::GetCoin mutates
        // cacheCoins (emplace-on-miss) so batching the LevelDB reads here
        // also warms the cache before the later verify loop reads from it.
        const size_t n_in = tx.vin.size();
        std::vector<Coin> coins(n_in);
        for (size_t i = 0; i < n_in; ++i) {
            if (!view.GetCoin(tx.vin[i].prevout, coins[i])) {
                return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-input-unknown");
            }
        }
        if (bench_on) {
            const auto now = Clock::now();
            LogPrint(BCLog::BENCH, "        - blsct prefetch %zu coins: %.2fms\n", n_in,
                     std::chrono::duration<double, std::milli>(now - t_init).count());
        }

        // Per-input prep runs serially: the aggregate-verify path below
        // (blsAggregateVerifyNoCheck via PublicKeys::VerifyBatch) already
        // parallelises miller-loop / hash-to-G2 across std::thread::
        // hardware_concurrency() internally. Adding an outer thread pool
        // here would spawn N workers that each contend with the library's
        // own N workers — observed regression: 0.53 ms/txin → 2.46 ms/txin
        // on a 752-input block (8-core host, 64 contending threads).
        for (size_t i = 0; i < n_in; ++i) {
            BLSCTSignatureChecker checker(&tx, i);
            ScriptError serror;
            uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

            if (!VerifyScript(tx.vin[i].scriptSig, coins[i].out.scriptPubKey, nullptr, flags, checker, &serror)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-script-check");
            }

            for (const auto& pair : checker.GetKeyMessagePairs()) {
                vPubKeys.emplace_back(pair.first);
                vMessages.emplace_back(pair.second.begin(), pair.second.end());
            }

            if (!coins[i].out.blsctData.spendingKey.IsZero()) {
                vPubKeys.emplace_back(coins[i].out.blsctData.spendingKey);
                auto in_hash = tx.vin[i].GetHash();
                vMessages.emplace_back(in_hash.begin(), in_hash.end());
            }

            if (coins[i].out.HasBLSCTRangeProof()) {
                balanceKey = balanceKey + coins[i].out.blsctData.rangeProof.Vs[0];
            } else {
                range_proof::Generators<Mcl> gen = gf.GetInstance(coins[i].out.tokenId);
                balanceKey = balanceKey + (gen.G * MclScalar(coins[i].out.nValue));
            }
        }
    }
    const auto t_after_inputs = Clock::now();
    const size_t pubkey_count_after_inputs = vPubKeys.size();

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
                range_proof::Generators<Mcl> gen = gf.GetInstance(TokenId(parsedPredicate.GetPublicKey().GetHash()));
                balanceKey = balanceKey + (gen.G * MclScalar(parsedPredicate.GetAmount()));
            } else if (parsedPredicate.IsCreateTokenPredicate()) {
                vPubKeys.emplace_back(parsedPredicate.GetPublicKey());
                vMessages.emplace_back(out_hash.begin(), out_hash.end());
            } else if (parsedPredicate.IsMintNftPredicate()) {
                vPubKeys.emplace_back(parsedPredicate.GetPublicKey());
                vMessages.emplace_back(out_hash.begin(), out_hash.end());
                range_proof::Generators<Mcl> gen = gf.GetInstance(TokenId(parsedPredicate.GetPublicKey().GetHash(), parsedPredicate.GetNftId()));
                balanceKey = balanceKey + (gen.G * MclScalar(1));
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
            range_proof::Generators<Mcl> gen = gf.GetInstance(out.tokenId);
            balanceKey = balanceKey - (gen.G * MclScalar(out.nValue));
        }
    }

    vMessages.emplace_back(blsct::Common::BLSCTBALANCE);
    vPubKeys.emplace_back(balanceKey);

    const auto t_after_outputs = Clock::now();
    const size_t total_pairs = vPubKeys.size();

    auto sigCheck = PublicKeys{vPubKeys}.VerifyBatch(vMessages, tx.txSig, true);

    const auto t_after_sig = Clock::now();

    if (!sigCheck)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-signature-check");

    if (verify_rp_inline) {
        auto& rp = GetSharedRPLogic();
        if (!rp.Verify(out_proofs)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "failed-rangeproof-check");
        }
        out_proofs.clear(); // consumed
    }

    const auto t_end = Clock::now();

    if (bench_on) {
        using D = std::chrono::duration<double, std::milli>;
        const size_t n_in = tx.vin.size();
        const size_t n_out = tx.vout.size();
        const size_t pubkeys_from_outputs = total_pairs - pubkey_count_after_inputs;
        LogPrint(BCLog::BENCH,
                 "        - blsct tx %s: vin=%zu vout=%zu pairs=%zu"
                 " init=%.2f inputs=%.2f outputs=%.2f sig_verify=%.2f rp_inline=%.2f total=%.2fms"
                 " (pairs_from_inputs=%zu pairs_from_outputs=%zu)\n",
                 tx.GetHash().ToString().substr(0, 10),
                 n_in, n_out, total_pairs,
                 D(t_init - t_begin).count(),
                 D(t_after_inputs - t_init).count(),
                 D(t_after_outputs - t_after_inputs).count(),
                 D(t_after_sig - t_after_outputs).count(),
                 D(t_end - t_after_sig).count(),
                 D(t_end - t_begin).count(),
                 pubkey_count_after_inputs - (blockReward > 0 ? 1 : 0),
                 pubkeys_from_outputs);
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
