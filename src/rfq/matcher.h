// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RFQ_MATCHER_H
#define BITCOIN_RFQ_MATCHER_H

#include <consensus/amount.h>
#include <rfq/quote.h>

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

} // namespace rfq

#endif // BITCOIN_RFQ_MATCHER_H
