// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RFQ_REQUEST_H
#define BITCOIN_RFQ_REQUEST_H

#include <blsct/public_key.h>
#include <consensus/amount.h>
#include <ctokens/tokenid.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>

namespace rfq {

//! A taker's request-for-quote, broadcast (PoW-stamped) over p2pmsg. The taker
//! wants to receive `size` units of `buy` paying with `sell`. `reply_key` is a
//! fresh per-request session pubkey makers encrypt their quote to.
struct RfqRequest {
    uint256 uuid;                 //!< unique per request; one-shot matching key
    TokenId buy;                  //!< token the taker wants to receive
    TokenId sell;                 //!< token the taker offers to pay with
    CAmount size{0};              //!< amount of `buy` requested
    int64_t expiry{0};            //!< unix seconds; quote collection deadline
    blsct::PublicKey reply_key;   //!< taker's session pubkey for encrypted replies

    SERIALIZE_METHODS(RfqRequest, obj)
    {
        READWRITE(obj.uuid, obj.buy, obj.sell, obj.size, obj.expiry, obj.reply_key);
    }
};

} // namespace rfq

#endif // BITCOIN_RFQ_REQUEST_H
