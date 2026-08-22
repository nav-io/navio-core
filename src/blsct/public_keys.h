// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_PUBLIC_KEYS_H
#define NAVIO_BLSCT_PUBLIC_KEYS_H

#include <blsct/public_key.h>

#include <span>
#include <vector>

namespace blsct {

class PublicKeys
{
public:
    // Non-owning view over the caller's pubkey vector. PublicKeys is a transient
    // verification helper; every use constructs it from a vector that outlives
    // the call, so holding a span avoids copying the whole vector (hundreds of
    // ~145-byte points) on the aggregate-verify hot path.
    PublicKeys(std::span<const PublicKey> pks): m_pks(pks) {}
    // Build the span from the vector explicitly rather than leaning on
    // span's range constructor: libc++ 14 (clang-14, the libnaviokernel CI
    // job) does not offer that conversion, so every call site here failed to
    // compile with "no known conversion from std::vector<PublicKey> to
    // std::span<const PublicKey>". The pointer+size constructor is part of
    // span's core interface and available everywhere.
    PublicKeys(const std::vector<PublicKey>& pks): m_pks(pks.data(), pks.size()) {}
    // A temporary vector would satisfy span's borrowed-range escape hatch
    // (element_type is const) and compile into a silent use-after-free once
    // the full-expression ends. Force callers to name the backing vector.
    PublicKeys(std::vector<PublicKey>&&) = delete;

    PublicKey Aggregate() const;

    // Basic scheme
    bool VerifyBalanceBatch(const Signature& sig) const;

    // Message augmentation scheme
    bool VerifyBatch(const std::vector<PublicKey::Message>& msgs, const Signature& sig, const bool& fVerifyTx = false) const;

private:
    // Core operations
    bool CoreAggregateVerify(const std::vector<PublicKey::Message>& msgs, const Signature& sig) const;

    std::span<const PublicKey> m_pks;
};

}

#endif  // NAVIO_BLSCT_PUBLICS_KEYS_H
