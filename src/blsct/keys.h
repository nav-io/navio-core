// Copyright (c) 2022 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KEY_H
#define KEY_H

#include <blsct/arith/point.h>
#include <blsct/arith/scalar.h>
#include <hash.h>
#include <key.h>
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <version.h>

namespace blsct {
static const std::string subAddressHeader = "SubAddress\0";

template <typename P>
class PublicKey
{
private:
    std::vector<unsigned char> data;

public:
    static constexpr size_t SIZE = 48;

    PublicKey() { data.clear(); }
    PublicKey(const P& pk) : data(pk.GetVch()) {}
    PublicKey(const std::vector<unsigned char>& pk) : data(pk) {}

    SERIALIZE_METHODS(PublicKey<P>, obj) { READWRITE(obj.data); }

    static PublicKey<P> Aggregate(std::vector<PublicKey<P>> vPk);

    uint256 GetHash() const;
    CKeyID GetID() const;

    std::string ToString() const;

    bool operator==(const PublicKey<P>& rhs) const;

    bool IsValid() const;

    bool GetG1Point(P& ret) const;
    std::vector<unsigned char> GetVch() const;
};

template <typename P>
class DoublePublicKey
{
private:
    PublicKey<P> vk;
    PublicKey<P> sk;

public:
    static constexpr size_t SIZE = 48 * 2;

    DoublePublicKey() {}
    DoublePublicKey(const P& vk_, const P& sk_) : vk(vk_.GetVch()), sk(sk_.GetVch()) {}
    DoublePublicKey(const std::vector<unsigned char>& vk_, const std::vector<unsigned char>& sk_) : vk(vk_), sk(sk_) {}

    SERIALIZE_METHODS(DoublePublicKey<P>, obj) { READWRITE(obj.vk.GetVch(), obj.sk.GetVch()); }

    uint256 GetHash() const;
    CKeyID GetID() const;

    bool GetViewKey(P& ret) const;
    bool GetSpendKey(P& ret) const;

    bool operator==(const DoublePublicKey<P>& rhs) const;

    bool IsValid() const;

    std::vector<unsigned char> GetVkVch() const;
    std::vector<unsigned char> GetSkVch() const;
    std::vector<unsigned char> GetVch() const;
};

template <typename P>
class PrivateKey
{
private:
    CPrivKey k;

public:
    static constexpr size_t SIZE = 32;

    PrivateKey() { k.clear(); }

    template <typename S>
    PrivateKey(S k_);

    PrivateKey(CPrivKey k_);

    SERIALIZE_METHODS(PrivateKey<P>, obj) { READWRITE(std::vector<unsigned char>(obj.k.begin(), obj.k.end())); }

    bool operator==(const PrivateKey<P>& rhs) const;

    template <typename S>
    P GetPoint() const;

    PublicKey<P> GetPublicKey() const;

    template <typename S>
    S GetScalar() const;

    template <typename S>
    bool IsValid() const;

    void SetToZero();

    friend class CCryptoKeyStore;
    friend class CBasicKeyStore;
};

} // namespace blsct

#endif // KEY_H
