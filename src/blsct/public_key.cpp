// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/common.h> // causes mutual dependency issue if included in the public_key header
#include <blsct/public_key.h>
#include <tinyformat.h>
#include <util/strencodings.h>

namespace blsct {
using Point = BlstG1Point;

uint256 PublicKey::GetHash() const
{
    HashWriter ss{};
    ss << GetVch();
    return ss.GetHash();
}

CKeyID PublicKey::GetID() const
{
    return CKeyID(Hash160(GetVch()));
}

Point PublicKey::GetG1Point() const
{
    return point;
}

std::string PublicKey::ToString() const
{
    return HexStr(GetVch());
};

bool PublicKey::operator==(const PublicKey& rhs) const
{
    return GetVch() == rhs.GetVch();
}

bool PublicKey::operator!=(const PublicKey& rhs) const
{
    return GetVch() != rhs.GetVch();
}

bool PublicKey::IsValid() const
{
    if (fValid == -1) {
        if (point.IsValid())
            const_cast<PublicKey*>(this)->fValid = 1;
    }
    return fValid == 1;
}

std::vector<unsigned char> PublicKey::GetVch() const
{
    return point.GetVch();
}

bool PublicKey::SetVch(const std::vector<unsigned char> vec)
{
    return point.SetVch(vec);
}

blst_p1_affine PublicKey::ToAffine() const
{
    blst_p1_affine aff{};
    blst_p1_to_affine(&aff, &point.GetUnderlying());
    return aff;
}

std::vector<uint8_t> PublicKey::AugmentMessage(const Message& msg) const
{
    auto pk_data = GetVch();
    std::vector<uint8_t> aug_msg;
    aug_msg.reserve(pk_data.size() + msg.size());
    aug_msg.insert(aug_msg.end(), pk_data.begin(), pk_data.end());
    aug_msg.insert(aug_msg.end(), msg.begin(), msg.end());
    return aug_msg;
}

bool PublicKey::CoreVerify(const Message& msg, const Signature& sig) const
{
    // e(pk, H(msg)) == e(G1, sig). An identity public key is rejected
    // (BLST_PK_IS_INFINITY), as is a signature outside the G2 subgroup.
    blst_p1_affine pk = ToAffine();
    blst_p2_affine s{};
    blst_p2_to_affine(&s, &sig.m_data);
    return blst_core_verify_pk_in_g1(&pk, &s, /*hash_or_encode=*/true,
                                     msg.data(), msg.size(),
                                     reinterpret_cast<const byte*>(BLS_SIG_G2_DST), BLS_SIG_G2_DST_LEN,
                                     nullptr, 0) == BLST_SUCCESS;
}

bool PublicKey::VerifyBalance(const Signature& sig) const
{
    return CoreVerify(Common::BLSCTBALANCE, sig);
}

bool PublicKey::Verify(const Message& msg, const Signature& sig) const
{
    auto aug_msg = AugmentMessage(msg);
    return CoreVerify(aug_msg, sig);
}

} // namespace blsct
