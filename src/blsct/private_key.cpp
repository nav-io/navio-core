// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BLS_ETH 1

#include <blsct/private_key.h>

namespace blsct {

PrivateKey::PrivateKey(Scalar k_)
{
    if (k_.IsZero()) {
        throw std::runtime_error("Private key needs to be a non-zero scalar");
    }
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
    return PublicKey(GetPoint());
}

PrivateKey::Scalar PrivateKey::GetScalar() const
{
    return Scalar(std::vector<unsigned char>(k.begin(), k.end()));
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
    blsSecretKey bls_sk { GetScalar().Underlying() };

    Signature sig;
    blsSign(&sig.m_data, &bls_sk, &msg[0], msg.size());
    return sig;
}

Signature PrivateKey::SignBalance() const
{
    return CoreSign(BLS12_381_Common::BLSCTBALANCE);
}

Signature PrivateKey::Sign(const Message& msg) const
{
    auto pk = GetPublicKey();
    auto aug_msg = pk.AugmentMessage(msg);
    auto sig = CoreSign(aug_msg);
    return sig;
}

}  // namespace blsct
