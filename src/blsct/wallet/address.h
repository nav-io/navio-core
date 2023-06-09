// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_ADDRESS_H
#define NAVCOIN_BLSCT_ADDRESS_H

#include <blsct/double_public_key.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <key_io.h>

namespace blsct {
static const std::string subAddressHeader = "SubAddress\0";

class SubAddressPool
{
public:
    int64_t nTime;
    CKeyID hashId;

    SubAddressPool() : nTime(GetTime()){};
    SubAddressPool(const CKeyID& hashIdIn) : nTime(GetTime()), hashId(hashIdIn){};


    SERIALIZE_METHODS(SubAddressPool, obj)
    {
        READWRITE(obj.nTime, obj.hashId);
    }
};

struct SubAddressIdentifier {
    uint64_t account;
    uint64_t address;
};

class SubAddress
{
private:
    DoublePublicKey pk;

public:
    SubAddress(const PrivateKey& viewKey, const PublicKey& spendKey, const SubAddressIdentifier& subAddressId);
    SubAddress(const DoublePublicKey& pk) : pk(pk){};

    bool IsValid() const;

    std::string GetString() const;
    CTxDestination GetDestination() const;
    DoublePublicKey GetKeys() const { return pk; };
};
} // namespace blsct

#endif // NAVCOIN_BLSCT_ADDRESS_H
