// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory_global.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(blsct_txfactory_global_tests)

BOOST_FIXTURE_TEST_CASE(create_output_test, TestingSetup)
{
    std::string destAddr = "nav14h85k6mf4l5fu3j4v0nuuswjwrz5entvzcw9jl3s8uknsndu0pfzaze4992n36uq7hpcy8yeuu854p0gmhq4m2u0tf5znazc527cxy4j7c39qxlc89wg4nca8pazkecx0p6wmu3pwrma3ercgrk8s7k4759q2thyq5";
    MclScalar blindingKey{ParseHex("42c0926471b3bd01ae130d9382c5fca2e2b5000abbf826a93132696ffa5f2c65")};

    auto out = blsct::CreateOutput(blsct::SubAddress(destAddr).GetKeys(), 1, "", TokenId(), blindingKey);

    BOOST_CHECK(out.out.blsctData.viewTag == 52098);
    BOOST_CHECK(HexStr(out.out.blsctData.spendingKey.GetVch()) == "90a498638b6d13a89b2dd1bbcb1caf419577878bff4c2d6426d602b9d74f3878d4a89feda5c2a59dc862a55c4e25a265");
    BOOST_CHECK(HexStr(out.out.blsctData.blindingKey.GetVch()) == "b96f2eae5089b87e1f9c39f49cccc779c840d861ab0a722d9597273c4c6e9f4075ce5562c82efba02f46146bf17bad72");
    BOOST_CHECK(HexStr(out.out.blsctData.ephemeralKey.GetVch()) == "935963399885ba1dd51dd272fb9be541896ac619570315e55f06c1e3a42d28ffb300fe6a3247d484bb491b25ecf7fb8a");
    BOOST_CHECK(out.gamma.GetString() == "37763c3ba24138ed73aafc33881e221d942bd81b20acc840033eb0a7bc0be4b5");
    BOOST_CHECK(out.blindingKey.GetString() == "42c0926471b3bd01ae130d9382c5fca2e2b5000abbf826a93132696ffa5f2c65");
}

BOOST_AUTO_TEST_SUITE_END()
