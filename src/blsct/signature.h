// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_SIGNATURE_H
#define NAVIO_BLSCT_SIGNATURE_H

#include <blst.h>
#include <blsct/arith/blst/blst_scalar.h>
#include <serialize.h>

#include <vector>

namespace blsct {

// BLS signature scheme parameters (min-pk: public keys in G1, signatures in
// G2, hash-to-curve per RFC 9380 with the "POP" ciphersuite tag).
// Consensus-critical: every signature on chain hashes messages under this DST.
inline constexpr const char* BLS_SIG_G2_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
inline constexpr size_t BLS_SIG_G2_DST_LEN = 43;

class Signature
{
public:
    Signature();
    Signature(const std::vector<uint8_t>& vch) {
        SetVch(vch);
    };

    static Signature Aggregate(const std::vector<blsct::Signature>& sigs);

    bool operator==(const Signature& b) const;
    bool IsZero() const;
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
        // Same policy as BlstG1Point::Unserialize: invalid encodings are a
        // deserialization error, except under the legacy-decode scope used
        // for binary-baked consensus parameters (genesis blobs).
        if (!SetVch(vec)) {
            if (BlstLegacyPointDecodeActive()) return; // SetVch already cleared to identity
            throw std::ios_base::failure("blsct::Signature: invalid or off-subgroup encoding");
        }
    }

    // G2 point in Jacobian coordinates; all-zero is the identity. Value-
    // initialised so blst's (MSan-invisible) assembly never writes into
    // poisoned memory.
    blst_p2 m_data{};

    static constexpr int SERIALIZATION_SIZE = 96;
};

} // namespace blsct

#endif // NAVIO_BLSCT_SIGNATURE_H
