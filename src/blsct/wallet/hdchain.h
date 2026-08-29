// Copyright (c) 2023-2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_WALLET_HDCHAIN_H
#define NAVIO_BLSCT_WALLET_HDCHAIN_H

#include <wallet/db.h>
#include <wallet/walletutil.h>

/* simple HD chain data model */
namespace blsct {
class HDChain
{
public:
    CKeyID seed_id;  //!< seed hash160
    CKeyID spend_id; //!< spend hash160
    CKeyID view_id;  //!< view hash160
    CKeyID blinding_id; //!< blinding hash160
    CKeyID token_id; //!< token hash160
    std::map<int64_t, uint64_t> nSubAddressCounter;

    static const int VERSION_HD_BASE = 1;
    static const int CURRENT_VERSION = VERSION_HD_BASE;
    int nVersion;

    HDChain() { SetNull(); }

    SERIALIZE_METHODS(HDChain, obj)
    {
        READWRITE(obj.nVersion, obj.seed_id, obj.spend_id, obj.view_id, obj.token_id, obj.nSubAddressCounter);
    }

    void SetNull()
    {
        nVersion = HDChain::CURRENT_VERSION;
        seed_id.SetNull();
        spend_id.SetNull();
        view_id.SetNull();
        blinding_id.SetNull();
        token_id.SetNull();
        nSubAddressCounter.clear();
    }

    bool operator==(const HDChain& chain) const
    {
        // blinding_id is deliberately excluded: SERIALIZE_METHODS never writes it, so a reloaded chain would never equal the one that was stored.
        return seed_id == chain.seed_id && spend_id == chain.spend_id && view_id == chain.view_id && token_id == chain.token_id && nSubAddressCounter == chain.nSubAddressCounter;
    }
};
} // namespace blsct

#endif // NAVIO_BLSCT_WALLET_HDCHAIN_H
