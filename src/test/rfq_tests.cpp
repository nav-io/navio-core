// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rfq/intent_store.h>
#include <rfq/matcher.h>
#include <rfq/order_cache.h>
#include <rfq/quote.h>
#include <rfq/request.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <validationinterface.h>

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

// ---- OrderCache ----

namespace {
//! A standing order whose half-tx spends `input_hash` and offers `fill`.
RfqQuote MakeOrder(const uint256& quote_id, const uint256& input_hash,
                   CAmount fill, CAmount sell_cost, int64_t order_expiry)
{
    RfqQuote q;
    q.quote_id = quote_id;
    q.fill = fill;
    q.sell_cost = sell_cost;
    q.order_expiry = order_expiry;
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::BLSCT_MARKER;
    mtx.vin.emplace_back(COutPoint(input_hash));
    mtx.vout.emplace_back();
    q.half_tx = MakeTransactionRef(mtx);
    return q;
}
} // namespace

BOOST_AUTO_TEST_CASE(order_store_find_expiry)
{
    OrderCache cache(/*now=*/1000);
    const uint256 qid = uint256::ONE;
    const uint256 input = InsecureRand256();

    // Store an order valid until t=5000.
    BOOST_CHECK(cache.StoreOrder(MakeOrder(qid, input, /*fill=*/1000, /*sell_cost=*/100, /*order_expiry=*/5000), /*now=*/1000));
    BOOST_CHECK_EQUAL(cache.Size(), 1u);
    BOOST_CHECK(cache.Contains(qid));

    // Duplicate quote_id rejected.
    BOOST_CHECK(!cache.StoreOrder(MakeOrder(qid, InsecureRand256(), 1000, 100, 5000), 1000));

    // Already-expired store rejected.
    BOOST_CHECK(!cache.StoreOrder(MakeOrder(InsecureRand256(), InsecureRand256(), 1000, 100, /*order_expiry=*/900), 1000));

    // FindMatching: request size <= fill matches; larger does not.
    RfqRequest req = MakeReq(TokA(), TokB(), 800, 0);
    BOOST_CHECK_EQUAL(cache.FindMatching(req, /*now=*/2000).size(), 1u);
    RfqRequest big = MakeReq(TokA(), TokB(), 2000, 0);
    BOOST_CHECK_EQUAL(cache.FindMatching(big, 2000).size(), 0u);

    // After expiry, find returns nothing and prunes.
    BOOST_CHECK_EQUAL(cache.FindMatching(req, /*now=*/6000).size(), 0u);
    BOOST_CHECK_EQUAL(cache.Size(), 0u);
}

BOOST_AUTO_TEST_CASE(order_max_ttl_caps_expiry)
{
    OrderCache cache(0);
    const uint256 qid = uint256::ONE;
    // Declared expiry far beyond 14 days; effective expiry is capped.
    BOOST_CHECK(cache.StoreOrder(MakeOrder(qid, InsecureRand256(), 1000, 100, /*order_expiry=*/100 * MAX_ORDER_TTL_SECONDS), /*now=*/0));
    // Just past 14 days -> pruned.
    BOOST_CHECK_EQUAL(cache.PruneExpired(MAX_ORDER_TTL_SECONDS + 1), 1u);
    BOOST_CHECK_EQUAL(cache.Size(), 0u);
}

BOOST_AUTO_TEST_CASE(order_ann_wire_roundtrip)
{
    // Exercises the exact serialize/deserialize the ORDER_ANN inbound handler
    // and broadcastorder RPC use: a standing-order quote (carrying a half-tx) is
    // sent as TX_WITH_WITNESS bytes and recovered the same way, then cached.
    RfqQuote q = MakeOrder(uint256::ONE, InsecureRand256(), /*fill=*/1000, /*sell_cost=*/100, /*order_expiry=*/5000);

    DataStream ss;
    ParamsStream sps{TX_WITH_WITNESS, ss};
    sps << q;
    auto bytes = MakeUCharSpan(ss);
    std::vector<uint8_t> body(bytes.begin(), bytes.end());

    DataStream rs{MakeByteSpan(body)};
    ParamsStream rps{TX_WITH_WITNESS, rs};
    RfqQuote recovered;
    rps >> recovered;
    BOOST_CHECK(recovered.quote_id == q.quote_id);
    BOOST_CHECK_EQUAL(recovered.fill, q.fill);
    BOOST_CHECK_EQUAL(recovered.sell_cost, q.sell_cost);
    BOOST_REQUIRE(recovered.half_tx != nullptr);

    OrderCache cache(/*now=*/1000);
    BOOST_CHECK(cache.StoreOrder(recovered, /*now=*/1000));
    BOOST_CHECK_EQUAL(cache.Size(), 1u);
}

BOOST_AUTO_TEST_CASE(order_spent_input_evicts)
{
    OrderCache cache(0);
    const uint256 qid = uint256::ONE;
    const uint256 input = InsecureRand256();
    BOOST_CHECK(cache.StoreOrder(MakeOrder(qid, input, 1000, 100, 5000), 0));

    auto block = std::make_shared<CBlock>();
    CMutableTransaction spender;
    spender.vin.emplace_back(COutPoint(input));
    block->vtx.push_back(MakeTransactionRef(spender));

    cache.BlockConnected(ChainstateRole::NORMAL, block, nullptr);
    BOOST_CHECK_EQUAL(cache.Size(), 0u);
}

// ---- MatcherRegistry ----

BOOST_AUTO_TEST_CASE(matcher_registry_lifecycle)
{
    MatcherRegistry reg;
    RfqRequest r = MakeReq(TokA(), TokB(), 1000, 5000);
    r.uuid = uint256::ONE;

    BOOST_CHECK(reg.OpenRequest(r));
    BOOST_CHECK(!reg.OpenRequest(r));            // uuid collision
    BOOST_CHECK_EQUAL(reg.Size(), 1u);
    BOOST_CHECK(reg.GetRequest(uint256::ONE).has_value());

    // Quotes for an unknown uuid are rejected.
    RfqQuote q = MakeQuote(1000, 95);
    q.uuid = uint256(uint64_t{99});
    q.quote_id = uint256(uint64_t{1});
    BOOST_CHECK(!reg.AddQuote(q));

    // Quotes for the open uuid are accepted; dup quote_id is one-shot rejected.
    q.uuid = uint256::ONE;
    BOOST_CHECK(reg.AddQuote(q));
    BOOST_CHECK(!reg.AddQuote(q));
    BOOST_CHECK_EQUAL(reg.GetQuotes(uint256::ONE).size(), 1u);

    // A second distinct quote.
    RfqQuote q2 = MakeQuote(1000, 90);
    q2.uuid = uint256::ONE;
    q2.quote_id = uint256(uint64_t{2});
    BOOST_CHECK(reg.AddQuote(q2));
    BOOST_CHECK_EQUAL(reg.GetQuotes(uint256::ONE).size(), 2u);

    // Lookup by id, then cancel.
    BOOST_CHECK(reg.GetQuote(uint256::ONE, uint256(uint64_t{2})).has_value());
    BOOST_CHECK(!reg.GetQuote(uint256::ONE, uint256(uint64_t{7})).has_value());
    BOOST_CHECK(reg.Cancel(uint256::ONE));
    BOOST_CHECK(!reg.Cancel(uint256::ONE));
    BOOST_CHECK_EQUAL(reg.Size(), 0u);
}

BOOST_AUTO_TEST_SUITE_END()
