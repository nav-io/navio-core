// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_PUBLIC_KEYS_H
#define NAVCOIN_BLSCT_PUBLIC_KEYS_H

#define BLS_ETH 1

#include <vector>
#include <blsct/public_key.h>

namespace blsct {

class PublicKeys
{
public:
    PublicKeys(const std::vector<PublicKey>& pks): m_pks(pks) {}

    // Message augmentation scheme
    bool VerifyBatch(const std::vector<PublicKey::Message>& msgs, const Signature& sig);

private:
    // Core operations
    static bool CoreAggregateVerify(
        const std::vector<PublicKey>& pks, const std::vector<PublicKey::Message>& msgs, const Signature& sig);

    std::vector<PublicKey> m_pks;
};

}

#endif  // NAVCOIN_BLSCT_PUBLICS_KEY_H
