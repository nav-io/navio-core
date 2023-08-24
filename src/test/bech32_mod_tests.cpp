// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bech32_mod.h>
#include <test/util/str.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(bech32_mod_tests)

BOOST_AUTO_TEST_CASE(bech32_mod_blsct_address)
{
    size_t data_size=33;
    printf("---> testing data size=%lu\n", data_size);

    std::string input_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    std::vector<uint8_t> data;
    data.resize(input_hex.size());
    for (size_t i=0; i<input_hex.size(); ++i) {
        data[i] = input_hex[i];
    }
    auto enc = bech32_mod::Encode(
        bech32_mod::Encoding::BECH32,
        "b",
        data
    );
    printf("enc size=%lu\n", enc.size());
    printf("enc=%s\n", enc.c_str());
    for (size_t i=0; i<enc.size(); ++i) {
        printf("enc[%lu]=%c\n", i, enc[i]);
    }
    auto dec = bech32_mod::Decode(enc);

    BOOST_CHECK(dec.encoding == bech32_mod::Encoding::BECH32);
    BOOST_CHECK(dec.hrp == "b");
    BOOST_CHECK(dec.data == data);
}

// BOOST_AUTO_TEST_CASE(bech32m_testvectors_valid)
// {
//     static const std::string CASES[] = {
//         "A1LQFN3A",
//         "a1lqfn3a",
//         "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
//         "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
//         "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
//         "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
//         "?1v759aa"
//     };
//     for (const std::string& str : CASES) {
//         const auto dec = bech32_mod::Decode(str);
//         BOOST_CHECK(dec.encoding == bech32_mod::Encoding::BECH32M);
//         std::string recode = bech32_mod::Encode(bech32_mod::Encoding::BECH32M, dec.hrp, dec.data);
//         BOOST_CHECK(!recode.empty());
//         BOOST_CHECK(CaseInsensitiveEqual(str, recode));
//     }
// }

// BOOST_AUTO_TEST_CASE(bech32_testvectors_invalid)
// {
//     static const std::string CASES[] = {
//         " 1nwldj5",
//         "\x7f""1axkwrx",
//         "\x80""1eym55h",
//         "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
//         "pzry9x0s0muk",
//         "1pzry9x0s0muk",
//         "x1b4n0q5v",
//         "li1dgmt3",
//         "de1lg7wt\xff",
//         "A1G7SGD8",
//         "10a06t8",
//         "1qzzfhee",
//         "a12UEL5L",
//         "A12uEL5L",
//         "abcdef1qpzrz9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
//         "test1zg69w7y6hn0aqy352euf40x77qddq3dc",
//     };
//     static const std::pair<std::string, std::vector<int>> ERRORS[] = {
//         {"Invalid character or mixed case", {0}},
//         {"Invalid character or mixed case", {0}},
//         {"Invalid character or mixed case", {0}},
//         {"Bech32 string too long", {90}},
//         {"Missing separator", {}},
//         {"Invalid separator position", {0}},
//         {"Invalid Base 32 character", {2}},
//         {"Invalid separator position", {2}},
//         {"Invalid character or mixed case", {8}},
//         {"Invalid checksum", {}}, // The checksum is calculated using the uppercase form so the entire string is invalid, not just a few characters
//         {"Invalid separator position", {0}},
//         {"Invalid separator position", {0}},
//         {"Invalid character or mixed case", {3, 4, 5, 7}},
//         {"Invalid character or mixed case", {3}},
//         {"Invalid Bech32 checksum", {11}},
//         {"Invalid Bech32 checksum", {9, 16}},
//     };
//     static_assert(std::size(CASES) == std::size(ERRORS), "Bech32 CASES and ERRORS should have the same length");

//     int i = 0;
//     for (const std::string& str : CASES) {
//         const auto& err = ERRORS[i];
//         const auto dec = bech32_mod::Decode(str);
//         BOOST_CHECK(dec.encoding == bech32_mod::Encoding::INVALID);
//         auto [error, error_locations] = bech32_mod::LocateErrors(str);
//         BOOST_CHECK_EQUAL(err.first, error);
//         BOOST_CHECK(err.second == error_locations);
//         i++;
//     }
// }

// BOOST_AUTO_TEST_CASE(bech32m_testvectors_invalid)
// {
//     static const std::string CASES[] = {
//         " 1xj0phk",
//         "\x7f""1g6xzxy",
//         "\x80""1vctc34",
//         "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
//         "qyrz8wqd2c9m",
//         "1qyrz8wqd2c9m",
//         "y1b0jsk6g",
//         "lt1igcx5c0",
//         "in1muywd",
//         "mm1crxm3i",
//         "au1s5cgom",
//         "M1VUXWEZ",
//         "16plkw9",
//         "1p2gdwpf",
//         "abcdef1l7aum6echk45nj2s0wdvt2fg8x9yrzpqzd3ryx",
//         "test1zg69v7y60n00qy352euf40x77qcusag6",
//     };
//     static const std::pair<std::string, std::vector<int>> ERRORS[] = {
//         {"Invalid character or mixed case", {0}},
//         {"Invalid character or mixed case", {0}},
//         {"Invalid character or mixed case", {0}},
//         {"Bech32 string too long", {90}},
//         {"Missing separator", {}},
//         {"Invalid separator position", {0}},
//         {"Invalid Base 32 character", {2}},
//         {"Invalid Base 32 character", {3}},
//         {"Invalid separator position", {2}},
//         {"Invalid Base 32 character", {8}},
//         {"Invalid Base 32 character", {7}},
//         {"Invalid checksum", {}},
//         {"Invalid separator position", {0}},
//         {"Invalid separator position", {0}},
//         {"Invalid Bech32m checksum", {21}},
//         {"Invalid Bech32m checksum", {13, 32}},
//     };
//     static_assert(std::size(CASES) == std::size(ERRORS), "Bech32m CASES and ERRORS should have the same length");

//     int i = 0;
//     for (const std::string& str : CASES) {
//         const auto& err = ERRORS[i];
//         const auto dec = bech32_mod::Decode(str);
//         BOOST_CHECK(dec.encoding == bech32_mod::Encoding::INVALID);
//         auto [error, error_locations] = bech32_mod::LocateErrors(str);
//         BOOST_CHECK_EQUAL(err.first, error);
//         BOOST_CHECK(err.second == error_locations);
//         i++;
//     }
// }

BOOST_AUTO_TEST_SUITE_END()
