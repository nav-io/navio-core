// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RFQ_INTENT_STORE_H
#define BITCOIN_RFQ_INTENT_STORE_H

#include <consensus/amount.h>
#include <ctokens/tokenid.h>
#include <rfq/request.h>
#include <sync.h>

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace rfq {

//! A maker's locally-configured, wallet-bound swap intent. Never gossiped. An
//! intent advertises *config* only — token pair, size band, minimum price,
//! expiry. (Per the privacy posture, wallet balance is not consulted at match
//! time, so RFQ probing cannot binary-search a maker's balance; it can only
//! learn the advertised config, which is the offer itself.)
struct Intent {
    uint64_t id{0};
    TokenId token_in;     //!< token the maker pays out
    TokenId token_out;    //!< token the maker wants to receive
    CAmount min_size{0};  //!< reject requests below this fill
    CAmount max_size{0};  //!< cap fill at this
    CAmount price_min{0}; //!< minimum out/in ratio, scaled (see Match)
    int64_t expiry{0};    //!< unix seconds; intent inactive after this
};

//! What a successful match yields: the fill amount and the price to quote.
struct Match {
    uint64_t intent_id{0};
    CAmount fill{0};       //!< units of the requested buy token to deliver
    CAmount sell_cost{0};  //!< units of sell token to charge (>= price_min basis)
};

//! Thread-safe, in-memory, wallet-local store of swap intents.
class IntentStore
{
public:
    //! Add an intent; returns its assigned id.
    uint64_t Add(const TokenId& token_in, const TokenId& token_out,
                 CAmount min_size, CAmount max_size, CAmount price_min, int64_t expiry)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Remove by id; true if it existed.
    bool Clear(uint64_t id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Snapshot of all intents.
    std::vector<Intent> List() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Find an intent matching `req` at time `now`. Config-only:
    //!  - intent.token_in == req.buy AND intent.token_out == req.sell
    //!    (maker pays out what the taker wants; receives what the taker offers),
    //!  - now < intent.expiry,
    //!  - intent.min_size <= req.size <= intent.max_size.
    //! On match, fill = req.size and sell_cost = req.size * price_min (the maker
    //! quotes at its floor price; callers may sweeten). Returns the first match.
    std::optional<Match> TryMatch(const RfqRequest& req, int64_t now) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    mutable Mutex m_mutex;
    uint64_t m_next_id GUARDED_BY(m_mutex){1};
    std::map<uint64_t, Intent> m_intents GUARDED_BY(m_mutex);
};

} // namespace rfq

#endif // BITCOIN_RFQ_INTENT_STORE_H
