// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLSCT_UNSIGNED_TRANSACTION_H
#define BLSCT_UNSIGNED_TRANSACTION_H

#include <blsct/arith/mcl/mcl.h>
#include <blsct/tokens/info.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/txfactory_global.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>

namespace blsct {

class UnsignedTransaction
{
private:
    // Inputs and outputs
    std::vector<UnsignedInput> m_inputs;
    std::vector<UnsignedOutput> m_outputs;
    CAmount m_fee{0};

public:
    UnsignedTransaction() = default;

    // Getters
    const std::vector<UnsignedInput>& GetInputs() const { return m_inputs; }
    const std::vector<UnsignedOutput>& GetOutputs() const { return m_outputs; }
    CAmount GetFee() const { return m_fee; }

    // Setters
    void AddInput(const UnsignedInput& input);
    void AddOutput(const UnsignedOutput& output);
    void SetFee(CAmount fee) { m_fee = fee; }

    // Serialization
    SERIALIZE_METHODS(UnsignedTransaction, obj)
    {
        READWRITE(obj.m_inputs, obj.m_outputs, obj.m_fee);
    }

    // Serialization helpers
    std::vector<unsigned char> Serialize() const;
    static std::optional<UnsignedTransaction> Deserialize(const std::vector<unsigned char>& data);

    // Signing
    std::optional<CTransaction> Sign() const;
};

} // namespace blsct

#endif // BLSCT_UNSIGNED_TRANSACTION_H