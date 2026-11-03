// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_WALLET_UNSIGNED_TRANSACTION_H
#define NAVIO_BLSCT_WALLET_UNSIGNED_TRANSACTION_H

#include <blsct/arith/blst/blst.h>
#include <blsct/tokens/info.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/txfactory_global.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>

#include <ios>

namespace blsct {

class UnsignedTransaction
{
private:
    // Serialization format version, written FIRST so a decoder can dispatch on
    // it (a decoder that predates this field cannot parse the blob; pre-release
    // unsigned transactions must be regenerated). Bump when the layout changes.
    //   1: inputs, outputs, fee, transcript_v2
    //   2: version 1 followed by emit_fee_output. Only written when
    //      emit_fee_output is false, so fee-bearing transactions keep the
    //      version 1 layout that existing decoders read.
    static constexpr uint8_t SER_VERSION_V1{1};
    static constexpr uint8_t SER_VERSION_V2{2};
    // Inputs and outputs
    std::vector<UnsignedInput> m_inputs;
    std::vector<UnsignedOutput> m_outputs;
    CAmount m_fee{0};
    // Whether the output range proofs use the v2 Fiat-Shamir transcript. Carried
    // so the signer can stamp BLSCT_PROOF_V2_MARKER on the finished transaction.
    bool m_transcript_v2{false};
    // Whether Sign() appends the OP_RETURN fee output and its fee signature.
    // False builds a fee-0 aggregation cover candidate (like TxFactoryBase::
    // BuildTx with emitFeeOutput=false): no fee output, so an initiator can
    // merge it into an aggregate whose only fee output is the initiator's.
    // The inputs must then balance the outputs exactly and the fee must be 0.
    bool m_emit_fee_output{true};

public:
    UnsignedTransaction() = default;

    // Getters
    const std::vector<UnsignedInput>& GetInputs() const { return m_inputs; }
    // Mutable accessor so callers (e.g. signblsctrawtransaction) can fill in
    // spending keys that were deferred at creation time by a watch-only wallet.
    std::vector<UnsignedInput>& GetInputs() { return m_inputs; }
    const std::vector<UnsignedOutput>& GetOutputs() const { return m_outputs; }
    CAmount GetFee() const { return m_fee; }
    bool GetTranscriptV2() const { return m_transcript_v2; }
    bool GetEmitFeeOutput() const { return m_emit_fee_output; }

    // Setters
    void AddInput(const UnsignedInput& input);
    void AddOutput(const UnsignedOutput& output);
    void SetFee(CAmount fee) { m_fee = fee; }
    void SetTranscriptV2(bool transcript_v2) { m_transcript_v2 = transcript_v2; }
    void SetEmitFeeOutput(bool emit_fee_output) { m_emit_fee_output = emit_fee_output; }

    // Serialization
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t ser_version = m_emit_fee_output ? SER_VERSION_V1 : SER_VERSION_V2;
        s << ser_version << m_inputs << m_outputs << m_fee << m_transcript_v2;
        if (ser_version >= SER_VERSION_V2) s << m_emit_fee_output;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t ser_version;
        s >> ser_version;
        if (ser_version != SER_VERSION_V1 && ser_version != SER_VERSION_V2) {
            throw std::ios_base::failure("UnsignedTransaction: unknown serialization version");
        }
        s >> m_inputs >> m_outputs >> m_fee >> m_transcript_v2;
        m_emit_fee_output = true;
        if (ser_version >= SER_VERSION_V2) s >> m_emit_fee_output;
    }

    // Serialization helpers
    std::vector<unsigned char> Serialize() const;
    static std::optional<UnsignedTransaction> Deserialize(const std::vector<unsigned char>& data);

    // Signing
    std::optional<CTransaction> Sign() const;
};

} // namespace blsct

#endif // NAVIO_BLSCT_WALLET_UNSIGNED_TRANSACTION_H