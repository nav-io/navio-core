// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// signining/verification part of implementation is based on:
// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html

#ifndef NAVCOIN_BLSCT_SIGNATURE_H
#define NAVCOIN_BLSCT_SIGNATURE_H

#define BLS_ETH 1

#include <bls/bls384_256.h>
#include <serialize.h>
#include <vector>
#include <version.h>

namespace blsct {

class Signature
{
public:
    static Signature Aggregate(const std::vector<blsct::Signature>& sigs);

    std::vector<unsigned char> GetVch() const;
    void SetVch(const std::vector<unsigned char>& b);

    unsigned int GetSerializeSize(int nVersion = PROTOCOL_VERSION) const
    {
        return ::GetSerializeSize(GetVch(), nVersion);
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, GetVch());
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        std::vector<unsigned char> vch;
        ::Unserialize(s, vch);
        SetVch(vch);
    }

    blsSignature m_data;
};

} // namespace blsct

#endif // NAVCOIN_BLSCT_SIGNATURE_H
