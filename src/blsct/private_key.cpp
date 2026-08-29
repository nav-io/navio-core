// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blst.h>
#include <blsct/private_key.h>

namespace blsct {

PrivateKey::PrivateKey(Scalar k_)
{
    k.resize(PrivateKey::SIZE);
    std::vector<unsigned char> v = k_.GetVch();
    memcpy(k.data(), &v.front(), k.size());
}

PrivateKey::PrivateKey(CPrivKey k_)
{
    k.resize(PrivateKey::SIZE);
    memcpy(k.data(), &k_.front(), k.size());
}

bool PrivateKey::operator==(const PrivateKey& rhs) const
{
    return k == rhs.k;
}

PrivateKey::Point PrivateKey::GetPoint() const
{
    return Point::GetBasePoint() * Scalar(std::vector<unsigned char>(k.begin(), k.end()));
}

PublicKey PrivateKey::GetPublicKey() const
{
    auto point = GetPoint();
    return point;
}

PrivateKey::Scalar PrivateKey::GetScalar() const
{
    auto ret = std::vector<unsigned char>(k.begin(), k.end());
    return ret;
}

bool PrivateKey::IsValid() const
{
    if (k.size() == 0) return false;
    Scalar s = GetScalar();
    return s.IsValid() && !s.IsZero();
}

void PrivateKey::SetToZero()
{
    k.clear();
}

Signature PrivateKey::CoreSign(const Message& msg) const
{
    // sig = sk * H(msg), H = hash-to-G2 under the BLS "POP" DST.
    blst_scalar sk{};
    blst_scalar_from_fr(&sk, &GetScalar().GetUnderlying());
    blst_p2 hash{};
    blst_hash_to_g2(&hash, msg.data(), msg.size(),
                    reinterpret_cast<const byte*>(BLS_SIG_G2_DST), BLS_SIG_G2_DST_LEN, nullptr, 0);
    Signature sig;
    blst_sign_pk_in_g1(&sig.m_data, &hash, &sk);
    return sig;
}

Signature PrivateKey::SignBalance() const
{
    return CoreSign(Common::BLSCTBALANCE);
}

Signature PrivateKey::SignFee() const
{
    return CoreSign(Common::BLSCTFEE);
}

Signature PrivateKey::Sign(const uint256& msg) const
{
    return Sign(Message(msg.begin(), msg.end()));
}

Signature PrivateKey::Sign(const Message& msg) const
{
    auto pk = GetPublicKey();
    auto aug_msg = pk.AugmentMessage(msg);
    auto sig = CoreSign(aug_msg);
    return sig;
}

bool PrivateKey::VerifyPubKey(const PublicKey& pk) const
{
    return GetPublicKey() == pk;
}

} // namespace blsct
