// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/tokens/info.h>
#include <consensus/amount.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(token_info_tests, BasicTestingSetup)

static blsct::TokenEntry MakeToken(CAmount totalSupply, CAmount supply = 0)
{
    blsct::TokenInfo info;
    info.type = blsct::TOKEN;
    info.nTotalSupply = totalSupply;
    return blsct::TokenEntry(info, supply);
}

BOOST_AUTO_TEST_CASE(mint_basic)
{
    auto token = MakeToken(/*totalSupply=*/1000);

    BOOST_CHECK(token.Mint(400));
    BOOST_CHECK_EQUAL(token.nSupply, 400);

    BOOST_CHECK(token.Mint(600)); // exactly reaches total supply
    BOOST_CHECK_EQUAL(token.nSupply, 1000);

    BOOST_CHECK(!token.Mint(1)); // would exceed total supply
    BOOST_CHECK_EQUAL(token.nSupply, 1000);
}

BOOST_AUTO_TEST_CASE(mint_disconnect_negative)
{
    auto token = MakeToken(/*totalSupply=*/1000, /*supply=*/500);

    // Disconnect reverses a prior mint by passing a negated amount.
    BOOST_CHECK(token.Mint(-300));
    BOOST_CHECK_EQUAL(token.nSupply, 200);

    // Cannot drive supply below zero.
    BOOST_CHECK(!token.Mint(-201));
    BOOST_CHECK_EQUAL(token.nSupply, 200);

    BOOST_CHECK(token.Mint(-200));
    BOOST_CHECK_EQUAL(token.nSupply, 0);
}

BOOST_AUTO_TEST_CASE(mint_rejects_out_of_money_range)
{
    auto token = MakeToken(/*totalSupply=*/MAX_MONEY);

    BOOST_CHECK(!token.Mint(MAX_MONEY + 1));
    BOOST_CHECK_EQUAL(token.nSupply, 0);

    // A value beyond MoneyRange must be rejected even if total supply is huge.
    BOOST_CHECK(!token.Mint(std::numeric_limits<CAmount>::max()));
    BOOST_CHECK_EQUAL(token.nSupply, 0);
}

BOOST_AUTO_TEST_CASE(mint_no_signed_overflow_at_extremes)
{
    // Regression: the old check computed `amount + nSupply` before testing it,
    // which is signed-overflow UB. Drive both operands near INT64_MAX and
    // confirm the mint is rejected (rather than wrapping to a "valid" value).
    blsct::TokenInfo info;
    info.type = blsct::TOKEN;
    info.nTotalSupply = std::numeric_limits<CAmount>::max();
    blsct::TokenEntry token(info, /*nSupply=*/std::numeric_limits<CAmount>::max() - 10);

    // nSupply is out of money range here, so any mint must be refused as
    // corrupt state rather than performing the wrapping addition.
    BOOST_CHECK(!token.Mint(std::numeric_limits<CAmount>::max()));
    BOOST_CHECK(!token.Mint(100));
}

BOOST_AUTO_TEST_SUITE_END()
