// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/strencodings.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

BOOST_AUTO_TEST_SUITE(util_string_tests)

BOOST_AUTO_TEST_CASE(ascii_case_insensitive_key_equal_test)
{
    AsciiCaseInsensitiveKeyEqual cmp;
    BOOST_CHECK(!cmp("A", "B"));
    BOOST_CHECK(!cmp("A", "b"));
    BOOST_CHECK(!cmp("a", "B"));
    BOOST_CHECK(!cmp("B", "A"));
    BOOST_CHECK(!cmp("B", "a"));
    BOOST_CHECK(!cmp("b", "A"));
    BOOST_CHECK(!cmp("A", "AA"));
    BOOST_CHECK(cmp("A-A", "a-a"));
    BOOST_CHECK(cmp("A", "A"));
    BOOST_CHECK(cmp("A", "a"));
    BOOST_CHECK(cmp("a", "a"));
    BOOST_CHECK(cmp("B", "b"));
    BOOST_CHECK(cmp("ab", "aB"));
    BOOST_CHECK(cmp("Ab", "aB"));
    BOOST_CHECK(cmp("AB", "ab"));

    // Use a character with value > 127
    // to ensure we don't trigger implicit-integer-sign-change
    BOOST_CHECK(!cmp("a", "\xe4"));
}

BOOST_AUTO_TEST_CASE(ascii_case_insensitive_hash_test)
{
    AsciiCaseInsensitiveHash hsh;
    BOOST_CHECK_NE(hsh("A"), hsh("B"));
    BOOST_CHECK_NE(hsh("AA"), hsh("A"));
    BOOST_CHECK_EQUAL(hsh("A"), hsh("a"));
    BOOST_CHECK_EQUAL(hsh("Ab"), hsh("aB"));
    BOOST_CHECK_EQUAL(hsh("A\xfe"), hsh("a\xfe"));
}

BOOST_AUTO_TEST_SUITE_END()
