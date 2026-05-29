// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rfq/intent_store.h>
#include <rfq/matcher.h>
#include <rfq/quote.h>
#include <rfq/request.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace rfq;

BOOST_FIXTURE_TEST_SUITE(rfq_tests, BasicTestingSetup)

namespace {
TokenId TokA() { return TokenId(uint256::ONE); }
TokenId TokB() { return TokenId(uint256(uint64_t{2})); }

RfqRequest MakeReq(const TokenId& buy, const TokenId& sell, CAmount size, int64_t expiry)
{
    RfqRequest r;
    r.uuid = uint256::ONE;
    r.buy = buy;
    r.sell = sell;
    r.size = size;
    r.expiry = expiry;
    return r;
}

RfqQuote MakeQuote(CAmount fill, CAmount sell_cost)
{
    RfqQuote q;
    q.fill = fill;
    q.sell_cost = sell_cost;
    return q;
}
} // namespace

// ---- IntentStore ----

BOOST_AUTO_TEST_CASE(intent_add_list_clear)
{
    IntentStore s;
    BOOST_CHECK_EQUAL(s.Size(), 0u);
    auto id = s.Add(TokA(), TokB(), 100, 1000, 100000000, /*expiry=*/2000);
    BOOST_CHECK_EQUAL(s.Size(), 1u);
    BOOST_CHECK_EQUAL(s.List().size(), 1u);
    BOOST_CHECK(s.Clear(id));
    BOOST_CHECK(!s.Clear(id));
    BOOST_CHECK_EQUAL(s.Size(), 0u);
}

BOOST_AUTO_TEST_CASE(intent_match_basic)
{
    IntentStore s;
    // Maker pays out TokA, wants TokB, price 0.1 TokB per TokA (scaled 1e8).
    s.Add(TokA(), TokB(), /*min*/100, /*max*/1000, /*price*/10000000, /*expiry*/2000);

    // Taker wants to BUY TokA, SELL TokB, size 500. Matches (intent pays TokA).
    auto m = s.TryMatch(MakeReq(TokA(), TokB(), 500, 0), /*now=*/1000);
    BOOST_REQUIRE(m.has_value());
    BOOST_CHECK_EQUAL(m->fill, 500);
    BOOST_CHECK_EQUAL(m->sell_cost, 50); // 500 * 0.1 (price_min 1e7 / scale 1e8)
}

BOOST_AUTO_TEST_CASE(intent_match_respects_bounds_and_pair_and_expiry)
{
    IntentStore s;
    s.Add(TokA(), TokB(), 100, 1000, 10000000, /*expiry=*/2000);

    // Below min_size: no match.
    BOOST_CHECK(!s.TryMatch(MakeReq(TokA(), TokB(), 50, 0), 1000).has_value());
    // Above max_size: no match.
    BOOST_CHECK(!s.TryMatch(MakeReq(TokA(), TokB(), 5000, 0), 1000).has_value());
    // Wrong pair (buy TokB): no match.
    BOOST_CHECK(!s.TryMatch(MakeReq(TokB(), TokA(), 500, 0), 1000).has_value());
    // Expired: now >= expiry, no match.
    BOOST_CHECK(!s.TryMatch(MakeReq(TokA(), TokB(), 500, 0), /*now=*/2000).has_value());
}

// ---- Matcher ranking ----

BOOST_AUTO_TEST_CASE(rank_by_price_picks_cheapest_full_fill)
{
    std::vector<RfqQuote> qs{
        MakeQuote(/*fill*/1000, /*cost*/100), // price 0.10
        MakeQuote(1000, 95),                  // price 0.095 <- best
        MakeQuote(1000, 110),                 // price 0.11
    };
    auto best = PickBest(qs, /*size=*/1000, /*min_fill_ratio=*/1.0, RankBy::Price);
    BOOST_REQUIRE(best.has_value());
    BOOST_CHECK_EQUAL(best->sell_cost, 95);
}

BOOST_AUTO_TEST_CASE(min_fill_ratio_filters_partials)
{
    std::vector<RfqQuote> qs{
        MakeQuote(/*fill*/600, /*cost*/50),  // cheapest unit price but partial
        MakeQuote(1000, 95),
    };
    // Require full fill: the 600 partial is dropped.
    auto full = PickBest(qs, 1000, /*min_fill_ratio=*/1.0, RankBy::Price);
    BOOST_REQUIRE(full.has_value());
    BOOST_CHECK_EQUAL(full->fill, 1000);

    // Allow >=50% partial: the cheaper 600 wins on price.
    auto partial = PickBest(qs, 1000, /*min_fill_ratio=*/0.5, RankBy::Price);
    BOOST_REQUIRE(partial.has_value());
    BOOST_CHECK_EQUAL(partial->fill, 600);
}

BOOST_AUTO_TEST_CASE(rank_by_fill_and_lowest_cost)
{
    std::vector<RfqQuote> qs{
        MakeQuote(800, 70),
        MakeQuote(1000, 99),
    };
    auto by_fill = PickBest(qs, 1000, 0.0, RankBy::Fill);
    BOOST_REQUIRE(by_fill.has_value());
    BOOST_CHECK_EQUAL(by_fill->fill, 1000);

    auto by_cost = PickBest(qs, 1000, 0.0, RankBy::LowestCost);
    BOOST_REQUIRE(by_cost.has_value());
    BOOST_CHECK_EQUAL(by_cost->sell_cost, 70);
}

BOOST_AUTO_TEST_CASE(no_quote_passes_filter)
{
    std::vector<RfqQuote> qs{MakeQuote(100, 10)};
    BOOST_CHECK(!PickBest(qs, 1000, 1.0, RankBy::Price).has_value());
    BOOST_CHECK(!PickBest({}, 1000, 0.0, RankBy::Price).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
