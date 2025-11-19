// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/unsigned_transaction.h>

namespace blsct {

void UnsignedTransaction::AddInput(const UnsignedInput& input)
{
    m_inputs.push_back(input);
}

void UnsignedTransaction::AddOutput(const UnsignedOutput& output)
{
    m_outputs.push_back(output);
}

std::vector<unsigned char> UnsignedTransaction::Serialize() const
{
    DataStream stream;
    stream << *this;
    return blsct::Common::DataStreamToVector(stream);
}

std::optional<UnsignedTransaction> UnsignedTransaction::Deserialize(const std::vector<unsigned char>& data)
{
    try {
        DataStream stream(data);
        UnsignedTransaction tx;
        stream >> tx;
        return tx;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<CTransaction> UnsignedTransaction::Sign() const
{
    try {
        // Create a mutable transaction
        CMutableTransaction tx;
        tx.nVersion |= CTransaction::BLSCT_MARKER;

        // Add inputs
        std::vector<Signature> txSigs;
        Scalar gammaAcc;

        // Add outputs first to calculate gamma
        for (const auto& out : m_outputs) {
            tx.vout.push_back(out.out);
            auto outHash = out.out.GetHash();

            if (out.out.HasBLSCTRangeProof()) {
                gammaAcc = gammaAcc - out.gamma;
            }
            if (out.out.HasBLSCTKeys()) {
                txSigs.push_back(PrivateKey(out.blindingKey).Sign(outHash));
            }

            if (out.type == TX_CREATE_TOKEN || out.type == TX_MINT_TOKEN) {
                txSigs.push_back(PrivateKey(out.tokenKey).Sign(outHash));
            }
        }

        // Add inputs and their signatures
        for (const auto& in : m_inputs) {
            tx.vin.push_back(in.in);
            gammaAcc = gammaAcc + in.gamma;
            txSigs.push_back(in.sk.Sign(in.in.GetHash()));
        }

        // Calculate fee based on transaction weight
        CAmount fee = m_fee;

        // Add fee output
        CTxOut fee_out{fee, CScript(OP_RETURN)};
        auto feeKey = blsct::PrivateKey(Scalar::Rand());
        fee_out.predicate = blsct::PayFeePredicate(feeKey.GetPublicKey()).GetVch();
        tx.vout.push_back(fee_out);

        // Add balance and fee signatures
        txSigs.push_back(PrivateKey(gammaAcc).SignBalance());
        txSigs.push_back(PrivateKey(feeKey).SignFee());

        // Aggregate all signatures
        tx.txSig = Signature::Aggregate(txSigs);

        return CTransaction(tx);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

} // namespace blsct