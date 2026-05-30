// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RFQ_MATCHER_H
#define BITCOIN_RFQ_MATCHER_H

#include <consensus/amount.h>
#include <rfq/quote.h>
#include <rfq/request.h>
#include <sync.h>
#include <uint256.h>

#include <map>
#include <optional>
#include <vector>

namespace rfq {

//! How a taker ranks collected quotes.
enum class RankBy {
    Price,      //!< ascending sell_cost/fill (default): cheapest unit cost wins
    Fill,       //!< largest fill first, price as tiebreak
    LowestCost, //!< smallest absolute sell_cost
};

//! Pick the best quote for a request of `size` from `quotes`.
//!  - Filter: drop quotes whose fill < size * min_fill_ratio.
//!  - Then rank per `by`. Ties (Price): larger fill, then earlier index.
//! `min_fill_ratio` in [0,1]: 1.0 requires a full fill; <1.0 allows partials.
//! Returns the chosen quote, or nullopt if none pass the filter.
std::optional<RfqQuote> PickBest(const std::vector<RfqQuote>& quotes,
                                 CAmount size,
                                 double min_fill_ratio = 1.0,
                                 RankBy by = RankBy::Price);

//! Taker-side registry of outstanding RFQ requests and the quotes collected for
//! each. The node owns one; the wallet drives it over RPC: open a request,
//! collect inbound quotes (deduped one-shot per quote_id within a uuid), list
//! the ranked quotes, then fetch one to combine + broadcast, or cancel.
class MatcherRegistry
{
public:
    //! Open a request for collection. Returns false if the uuid already exists.
    bool OpenRequest(const RfqRequest& req) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Record an inbound quote for an open request. Returns false if the uuid is
    //! unknown or the quote_id was already seen (one-shot per quote).
    bool AddQuote(const RfqQuote& q) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! All quotes collected for `uuid` (unranked snapshot).
    std::vector<RfqQuote> GetQuotes(const uint256& uuid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! The request itself, if open.
    std::optional<RfqRequest> GetRequest(const uint256& uuid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Look up a specific collected quote by (uuid, quote_id).
    std::optional<RfqQuote> GetQuote(const uint256& uuid, const uint256& quote_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Drop a request and its quotes. Returns true if it existed.
    bool Cancel(const uint256& uuid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Open request uuids.
    std::vector<uint256> ListRequests() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Active {
        RfqRequest req;
        std::map<uint256, RfqQuote> quotes; // quote_id -> quote
    };
    mutable Mutex m_mutex;
    std::map<uint256, Active> m_active GUARDED_BY(m_mutex);
};

} // namespace rfq

#endif // BITCOIN_RFQ_MATCHER_H
