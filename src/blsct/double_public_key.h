// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_DOUBLE_PUBLIC_KEY_H
#define NAVIO_BLSCT_DOUBLE_PUBLIC_KEY_H

#include <blsct/arith/blst/blst.h>
#include <blsct/public_key.h>

namespace blsct {

class DoublePublicKey
{
private:
    using Point = BlstG1Point;

    PublicKey vk;
    PublicKey sk;
    bool is_fully_built = false;

public:
    static constexpr size_t SIZE = blsct::PublicKey::SIZE * 2;

    DoublePublicKey() : is_fully_built(true) {}
    DoublePublicKey(const PublicKey& vk_, const PublicKey& sk_) : vk(vk_), sk(sk_), is_fully_built(true) {}
    DoublePublicKey(const Point& vk_, const Point& sk_) : vk(vk_), sk(sk_), is_fully_built(true) {}

    DoublePublicKey(const std::vector<unsigned char>& vk_, const std::vector<unsigned char>& sk_) : vk(vk_), sk(sk_)
    {
        BlstG1Point p;
        is_fully_built = p.SetVch(vk_) && p.SetVch(sk_);
    }

    DoublePublicKey(const std::vector<unsigned char>& keys);

    SERIALIZE_METHODS(DoublePublicKey, obj) { READWRITE(obj.vk, obj.sk); }

    uint256 GetHash() const;
    CKeyID GetID() const;

    bool GetViewKey(Point& ret) const;
    bool GetSpendKey(Point& ret) const;

    bool GetViewKey(PublicKey& ret) const;
    bool GetSpendKey(PublicKey& ret) const;

    bool operator==(const DoublePublicKey& rhs) const;
    bool operator<(const DoublePublicKey& rhs) const;

    bool IsValid() const;

    //! True when the key is valid AND neither half is the point at infinity.
    //! IsValid() only reports that both halves deserialized; an address
    //! encoding the identity for either key decodes fine, but an output built
    //! for it has publicly derivable ownership keys -- i.e. anyone-can-spend.
    //! Every path that turns a user-supplied destination into an output has to
    //! check this, not just IsValid().
    bool HasNonIdentityKeys() const;

    std::vector<unsigned char> GetVkVch() const;
    std::vector<unsigned char> GetSkVch() const;
    std::vector<unsigned char> GetVch() const;
};

} // namespace blsct

#endif // NAVIO_BLSCT_DOUBLE_PUBLIC_KEY_H
