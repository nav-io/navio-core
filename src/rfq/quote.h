// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RFQ_QUOTE_H
#define BITCOIN_RFQ_QUOTE_H

#include <blsct/public_key.h>
#include <blsct/signature.h>
#include <consensus/amount.h>
#include <ctokens/tokenid.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>

namespace rfq {

//! A maker's reply to an RfqRequest: an unbalanced half-tx offering `fill` units
//! of the requested `buy` token in exchange for `sell_cost` of the `sell` token.
//! Encrypted to the request's reply_key before going on the wire.
struct RfqQuote {
    uint256 uuid;                  //!< matches the RfqRequest
    uint256 quote_id;              //!< unique per quote (dedupe within a request)
    CTransactionRef half_tx;       //!< maker's unbalanced half
    TokenId buy;                   //!< token delivered to the taker (== request buy)
    TokenId sell;                  //!< token charged to the taker (== request sell)
    CAmount fill{0};               //!< units of `buy` delivered (>= 0)
    CAmount sell_cost{0};          //!< units of `sell` the taker must pay (> 0)
    int64_t order_expiry{0};       //!< quote valid until this unix time
    blsct::PublicKey session_eph;  //!< maker's session pubkey (self-sig identity)
    blsct::Signature maker_sig;    //!< sig over (uuid, half_tx hash, order_expiry)

    SERIALIZE_METHODS(RfqQuote, obj)
    {
        READWRITE(obj.uuid, obj.quote_id, obj.half_tx, obj.buy, obj.sell, obj.fill,
                  obj.sell_cost, obj.order_expiry, obj.session_eph, obj.maker_sig);
    }

    //! Price in units of `sell` per unit of `buy`. Lower is better for the taker.
    //! Returns +inf-ish (max) for a zero fill so it sorts last under rank_by=price.
    double Price() const
    {
        if (fill <= 0) return static_cast<double>(1e18);
        return static_cast<double>(sell_cost) / static_cast<double>(fill);
    }
};

} // namespace rfq

#endif // BITCOIN_RFQ_QUOTE_H
