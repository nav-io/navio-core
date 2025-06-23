// src/blsct/wallet/balance_proof.h
#ifndef BITCOIN_BLSCT_WALLET_BALANCE_PROOF_H
#define BITCOIN_BLSCT_WALLET_BALANCE_PROOF_H

#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <coins.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <wallet/wallet.h>

namespace blsct {

class BalanceProof
{
private:
    std::vector<COutPoint> m_outpoints;
    CAmount m_min_amount;
    bulletproofs_plus::RangeProof<Mcl> m_proof;

public:
    BalanceProof() = default;
    BalanceProof(const std::vector<COutPoint>& outpoints, CAmount min_amount, const bulletproofs_plus::RangeProof<Mcl>& proof)
        : m_outpoints(outpoints), m_min_amount(min_amount), m_proof(proof) {}

    BalanceProof(const std::vector<COutPoint>& outpoints, CAmount min_amount, const wallet::CWallet& wallet)
    {
        m_outpoints = outpoints;
        m_min_amount = min_amount;

        // Sum up all commitments from the outputs
        MclG1Point sum_commitment;
        Elements<MclScalar> values;
        for (const auto& outpoint : outpoints) {
            const wallet::CWalletTx* wtx = wallet.GetWalletTx(outpoint.hash);
            if (!wtx) {
                throw std::runtime_error("Outpoint not found in wallet");
            }
            if (outpoint.n >= wtx->tx->vout.size()) {
                throw std::runtime_error("Invalid output index");
            }
            const CTxOut& txout = wtx->tx->vout[outpoint.n];
            if (!txout.HasBLSCTRangeProof()) {
                throw std::runtime_error("Outpoint does not have BLSCT range proof");
            }
            sum_commitment = sum_commitment + txout.blsctData.rangeProof.Vs[0];
            auto recoveryData = wtx->GetBLSCTRecoveryData(outpoint.n);
            values.Add(MclScalar(recoveryData.amount));
        }

        // Create range proof
        bulletproofs_plus::RangeProofLogic<Mcl> prover;
        range_proof::GammaSeed<Mcl> nonce(sum_commitment);
        std::vector<uint8_t> message;
        m_proof = prover.Prove(values, nonce, message, TokenId(), MclScalar(min_amount));
    }

    const std::vector<COutPoint>& GetOutpoints() const { return m_outpoints; }
    CAmount GetMinAmount() const { return m_min_amount; }
    const bulletproofs_plus::RangeProof<Mcl>& GetProof() const { return m_proof; }

    bool Verify(const CCoinsViewCache& view) const
    {
        // Sum up all commitments from the outputs
        MclG1Point sum_commitment;
        for (const auto& outpoint : m_outpoints) {
            Coin coin;
            if (!view.GetCoin(outpoint, coin)) {
                return false;
            }
            if (!coin.out.HasBLSCTRangeProof()) {
                return false;
            }
            sum_commitment = sum_commitment + coin.out.blsctData.rangeProof.Vs[0];
        }

        // Create a range proof with seed for verification
        bulletproofs_plus::RangeProofWithSeed<Mcl> proof(m_proof, TokenId(), MclScalar(m_min_amount));
        std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>> proofs;
        proofs.push_back(proof);

        // Verify the range proof
        bulletproofs_plus::RangeProofLogic<Mcl> prover;
        return prover.Verify(proofs);
    }

    SERIALIZE_METHODS(BalanceProof, obj)
    {
        READWRITE(obj.m_outpoints, obj.m_min_amount, obj.m_proof);
    }
};

} // namespace blsct

#endif // BITCOIN_BLSCT_WALLET_BALANCE_PROOF_H