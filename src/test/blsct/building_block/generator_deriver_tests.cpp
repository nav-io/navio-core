// Copyright (c) 2023 The Navcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_UNIT_TEST
#define BLS_ETH 1

#include <blsct/arith/mcl/mcl.h>
#include <ctokens/tokenid.h>
#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <blsct/building_block/generator_deriver.h>

using Point = Mcl::Point;

BOOST_FIXTURE_TEST_SUITE(generator_deriver_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_derive)
{
    Point g = Point::GetBasePoint();

    std::vector<Point> xs;

    GeneratorDeriver deriver("pro-micro");

    for (size_t i=0; i<10; ++i) {
        auto p = deriver.Derive(g, i, std::nullopt);
        xs.push_back(p);
    }

    // use token id
    TokenId token_id(uint256(123));
    for (size_t i=0; i<10; ++i) {
        auto p = deriver.Derive(g, i, token_id);
        xs.push_back(p);
    }

    // use different base point
    Point gg = g + g;
    for (size_t i=0; i<10; ++i) {
        auto p = deriver.Derive(gg, i, token_id);
        xs.push_back(p);
    }

    // all derived points should be different
    for (size_t i=0; i<xs.size()-1; ++i) {
        for (size_t j=i+1; j<xs.size(); ++j) {
            BOOST_CHECK(xs[i] != xs[j]);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
