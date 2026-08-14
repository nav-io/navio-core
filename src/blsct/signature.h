// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// signining/verification part of implementation is based on:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html

#ifndef NAVIO_BLSCT_SIGNATURE_H
#define NAVIO_BLSCT_SIGNATURE_H

#define BLS_ETH 1

#include <bls/bls384_256.h>
#include <blsct/arith/mcl/mcl_scalar.h>
#include <serialize.h>

#include <vector>

namespace blsct {

class Signature
{
public:
    Signature();
    Signature(const std::vector<uint8_t>& vch) {
        SetVch(vch);
    };

    static Signature Aggregate(const std::vector<blsct::Signature>& sigs);

    bool operator==(const Signature& b) const;
    std::vector<uint8_t> GetVch() const;
    // Returns false on undecodable or off-subgroup input; the previous
    // behaviour silently cleared the signature to the identity point.
    bool SetVch(const std::vector<uint8_t>& b);

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        auto vec = GetVch();
        s.write(MakeByteSpan(vec));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        std::vector<unsigned char> vec(SERIALIZATION_SIZE);
        s.read(MakeWritableByteSpan(vec));
        // Same policy as MclG1Point::Unserialize: invalid encodings are a
        // deserialization error, except under the legacy-decode scope used
        // for binary-baked consensus parameters (genesis blobs).
        if (!SetVch(vec)) {
            if (MclLegacyPointDecodeActive()) return; // SetVch already cleared to identity
            throw std::ios_base::failure("blsct::Signature: invalid or off-subgroup encoding");
        }
    }

    blsSignature m_data;

    static constexpr int SERIALIZATION_SIZE = 96;
};

} // namespace blsct

#endif // NAVIO_BLSCT_SIGNATURE_H
