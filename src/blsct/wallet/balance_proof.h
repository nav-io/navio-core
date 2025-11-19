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
    blsct::Signature m_signature;
    uint16_t m_index;

public:
    BalanceProof() = default;
    BalanceProof(const std::vector<COutPoint>& outpoints, CAmount min_amount, const bulletproofs_plus::RangeProof<Mcl>& proof, const blsct::Signature& signature)
        : m_outpoints(outpoints), m_min_amount(min_amount), m_proof(proof), m_signature(signature), m_index(0) {}

    BalanceProof(const std::vector<COutPoint>& outpoints, CAmount min_amount, const wallet::CWallet& wallet, const blsct::Message& additional_commitment)
    {
        m_outpoints = outpoints;
        m_min_amount = min_amount;

        // Sum up all commitments from the outputs
        MclScalar value = 0;
        MclScalar gamma = 0;

        if (outpoints.empty()) {
            throw std::runtime_error("No outpoints provided");
        }

        const auto& blsct_km = const_cast<wallet::CWallet&>(wallet).GetOrCreateBLSCTKeyMan();
        blsct::PrivateKey private_key;
        bool has_private_key = false;
        uint16_t index = 0;

        for (const auto& outpoint : outpoints) {
            const wallet::CWalletTx* wtx = wallet.GetWalletTx(outpoint.hash);
            if (!wtx) {
                throw std::runtime_error("Outpoint not found in wallet");
            }

            if (outpoint.n >= wtx->tx->vout.size()) {
                throw std::runtime_error("Invalid output index");
            }
            const CTxOut& txout = wtx->tx->vout[outpoint.n];
            if (!has_private_key) {
                has_private_key = blsct_km->GetSpendingKeyForOutput(txout, private_key);
                m_index = index;
            }
            if (!txout.HasBLSCTRangeProof()) {
                throw std::runtime_error("Outpoint does not have BLSCT range proof");
            }
            auto recoveryData = wtx->GetBLSCTRecoveryData(outpoint.n);
            value = value + MclScalar(recoveryData.amount);
            gamma = gamma + MclScalar(recoveryData.gamma);
            index++;
        }

        // Create range proof
        bulletproofs_plus::RangeProofLogic<Mcl> prover;
        range_proof::GammaSeed<Mcl> nonce(Elements<MclScalar>{1, gamma});
        std::vector<uint8_t> message;
        m_proof = prover.Prove({1, value}, nonce, message, TokenId(), MclScalar(min_amount));
        m_signature = private_key.Sign(additional_commitment);
    }

    const std::vector<COutPoint>& GetOutpoints() const { return m_outpoints; }
    CAmount GetMinAmount() const { return m_min_amount; }
    const bulletproofs_plus::RangeProof<Mcl>& GetProof() const { return m_proof; }

    bool Verify(const CCoinsViewCache& view, const blsct::Message& additional_commitment) const
    {
        // Sum up all commitments from the outputs
        MclG1Point sum_commitment;
        MclG1Point public_key;
        uint16_t index = 0;
        for (const auto& outpoint : m_outpoints) {
            Coin coin;
            if (!view.GetCoin(outpoint, coin)) {
                return false;
            }
            if (!coin.out.HasBLSCTRangeProof()) {
                return false;
            }
            if (index == m_index) {
                public_key = coin.out.blsctData.spendingKey;
            }
            sum_commitment = sum_commitment + coin.out.blsctData.rangeProof.Vs[0];
            index++;
        }

        const_cast<bulletproofs_plus::RangeProof<Mcl>&>(m_proof).Vs.Clear();
        const_cast<bulletproofs_plus::RangeProof<Mcl>&>(m_proof).Vs.Add(sum_commitment);

        // Create a range proof with seed for verification
        bulletproofs_plus::RangeProofWithSeed<Mcl> proof(m_proof, TokenId(), MclScalar(m_min_amount));
        std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>> proofs;
        proofs.push_back(proof);

        // Verify the range proof
        bulletproofs_plus::RangeProofLogic<Mcl> prover;
        return prover.Verify(proofs) && blsct::PublicKey(public_key).Verify(additional_commitment, m_signature);
    }

    SERIALIZE_METHODS(BalanceProof, obj)
    {
        READWRITE(obj.m_outpoints, obj.m_min_amount, obj.m_proof, obj.m_signature, obj.m_index);
    }
};

} // namespace blsct

#endif // BITCOIN_BLSCT_WALLET_BALANCE_PROOF_H