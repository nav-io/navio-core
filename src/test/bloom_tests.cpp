// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/bloom.h>

#include <clientversion.h>
#include <common/system.h>
#include <key.h>
#include <key_io.h>
#include <merkleblock.h>
#include <primitives/block.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bloom_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize)
{
    CBloomFilter filter(3, 0.01, 0, BLOOM_UPDATE_ALL);

    BOOST_CHECK_MESSAGE( !filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter should be empty!");
    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")), "Bloom filter doesn't contain just-inserted object (3)!");

    DataStream stream{};
    stream << filter;

    std::vector<uint8_t> expected = ParseHex("03614e9b050000000000000001");
    auto result{MakeUCharSpan(stream)};

    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());

    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize_with_tweak)
{
    // Same test as bloom_create_insert_serialize, but we add a nTweak of 100
    CBloomFilter filter(3, 0.01, 2147483649UL, BLOOM_UPDATE_ALL);

    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")), "Bloom filter doesn't contain just-inserted object (3)!");

    DataStream stream{};
    stream << filter;

    std::vector<uint8_t> expected = ParseHex("03ce4299050000000100008001");
    auto result{MakeUCharSpan(stream)};

    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_key)
{
    std::string strSecret = std::string("5Kg1gnAjaLfKiwhhPpGS3QfRg2m6awQvaj98JCZBZQ5SuS2F15C");
    CKey key = DecodeSecret(strSecret);
    CPubKey pubkey = key.GetPubKey();
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CBloomFilter filter(2, 0.001, 0, BLOOM_UPDATE_ALL);
    filter.insert(vchPubKey);
    uint160 hash = pubkey.GetID();
    filter.insert(hash);

    DataStream stream{};
    stream << filter;

    std::vector<unsigned char> expected = ParseHex("038fc16b080000000000000001");
    auto result{MakeUCharSpan(stream)};

    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_match)
{
    // Random real transaction (7ccb890daa20b21cce3e5f0cf58c5cbecee016229334196d51c49002a35576cd)
    DataStream stream{
        ParseHex("01000000010b26e9b7735eb6aabdf358bab62f9816a21ba9ebdb719d5299e88607d722c1908b4830450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a0141046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339ffffffff021bff3d11000000001976a91404943fdd508053c75000106d3bc6e2754dbcff1988ac2f15de00000000001976a914a266436d2965547608b9e15d9032a7b9d64fa43188ac00000000"),
    };
    CTransaction tx(deserialize, TX_WITH_WITNESS, stream);

    // and one which spends it (bc822bdedeb99a9cf71ebcf6dd1118a3c2076ab6cbcfc1cdadefe08ad5e7472d)
    DataStream spendStream{ParseHex("0100000001eb4709b2f47c10c69373f98d0368cfdb074f114f46ef565969e4d1772e4585b08c493046022100da0dc6aecefe1e06efdf05773757deb168820930e3b0d03f46f5fcf150bf990c022100d25b5c87040076e4f253f8262e763e2dd51e7ff0be157727c4bc42807f17bd39014104e6c26ef67dc610d2cd192484789a6cf9aea9930b944b7e2db5342b9d9e5b9ff79aff9a2ee1978dd7fd01dfc522ee02283d3b06a9d03acf8096968d7dbb0f9178ffffffff028ba7940e000000001976a914badeecfdef0507247fc8f74241d73bc039972d7b88ac4094a802000000001976a914c10932483fec93ed51f5fe95e72559f2cc7043f988ac00000000")};
    CTransaction spendingTx(deserialize, TX_WITH_WITNESS, spendStream);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0xb085452e77d1e4695956ef464f114f07dbcf68038df97393c6107cf4b20947eb")));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match output hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // byte-reversed tx hash
    filter.insert(ParseHex("eb4709b2f47c10c69373f98d0368cfdb074f114f46ef565969e4d1772e4585b0"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match manually serialized tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("30450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a01"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input signature");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input pub key");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("04943fdd508053c75000106d3bc6e2754dbcff19"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match output address");
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(spendingTx), "Simple Bloom filter didn't add output");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("a266436d2965547608b9e15d9032a7b9d64fa431"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match output address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(TxidFromString("0x90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b")));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    COutPoint prevOutPoint(TxidFromString("0x90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"));
    {
        std::vector<unsigned char> data(32);
        memcpy(data.data(), prevOutPoint.hash.begin(), 32);
        filter.insert(data);
    }
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match manually serialized COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("00000009e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436")));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("0000006d2965547608b9e15d9032a7b9d64fa431"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(TxidFromString("0x90c122d70786e899529d71dbeea91ba216982fb6ba58f3bdaab65e73b7e9260b")));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched COutPoint for an output we didn't care about");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(TxidFromString("0x000000d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b")));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched COutPoint for an output we didn't care about");
}

BOOST_AUTO_TEST_CASE(merkle_block_1)
{
    CBlock block = getBlock13b8a();
    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the last transaction
    filter.insert(COutPoint(uint256S("0xb236fed5e50b68db610b3fbc432540a4c3fdbea4138c3ae8bffdc2e3b34ab00d")));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK_EQUAL(merkleBlock.header.GetHash().GetHex(), block.GetHash().GetHex());

    BOOST_CHECK_EQUAL(merkleBlock.vMatchedTxn.size(), 1U);
    std::pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x92787a1e892b862764b2e11bbd7b2c22f649047d864489cd0b2967e4949fb509"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 8);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Also match the 8th transaction
    filter.insert(COutPoint(uint256S("0xf15c9ce586842918baff132e1de46fbd44a97cda6169d6215624e7be3521f14e")));
    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1] == pair);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x36cb04533fe36171b3dbb00e8b054948b350f095edc2527496fbb1ee1bc76087"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 7);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_2)
{
    // Random real block (000000005a4ded781e667e06ceefafb71410b511fe0d5adc3e5a27ecbec34ae6)
    // With 4 txes
    CBlock block;
    DataStream stream{
        ParseHex("0100000075616236cc2126035fadb38deb65b9102cc2c41c09cdf29fc0519068000000006c5d6d366b2d42ad68bffce9b63ddf4996a571eba52425a238c58de8048fb43bd4d26e49ffff001d00f0a44104010000000100000000000000000000000000000000000000000000000000000000000000000804ffff001d029105ffffffff0100f2052a010000004341046d8709a041d34357697dfcb30a9d05900a6294078012bf3bb09c6f9b525f1d16d5503d7905db1ada9501446ea00728668fc5719aa80be2fdfc8a858a4dbdd4fbac00000000010000000255605dc6f5c3dc148b6da58442b0b2cd422be385eab2ebea4119ee9c268d283549483045022100aa46504baa86df8a33b1192b1b9367b4d729dc41e389f2c04f3e5c7f0559aae702205e82253a54bf5c4f65b7428551554b2045167d6d206dfe6a2e198127d3f7df1501ffffffff55605dc6f5c3dc148b6da58442b0b2cd422be385eab2ebea4119ee9c268d28354847304402202329484c35fa9d6bb32a55a70c0982f606ce0e3634b69006138683bcd12cbb6602200c28feb1e2555c3210f1dddb299738b4ff8bbe9667b68cb8764b5ac17b7adf0001ffffffff0200e1f505000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00180d8f000000004341044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac000000000100000002add5876bbe324adf5aea9b1f4b08983758f7e039cb23f5c252ec066ed82545484847304402205d6058484157235b06028c30736c15613a28bdb768ee628094ca8b0030d4d6eb0220328789c9a2ec27ddaec0ad5ef58efded42e6ea17c2e1ce838f3d6913f5e95db601ffffffff3be5674f2fcb7ee8f80731e41d37080ae8ad82a1a651f69a7b0db107dd6be4844a493046022100c45af050d3cea806cedd0ab22520c53ebe63b987b8954146cdca42487b84bdd6022100b9b027716a6b59e640da50a864d6dd8a0ef24c76ce62391fa3eabaf4d2886d2d01ffffffff0200e1f505000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00180d8f000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac000000000100000002add5876bbe324adf5aea9b1f4b08983758f7e039cb23f5c252ec066ed825454848473044022016e7a727a061ea2254a6c358376aaa617ac537eb836c77d646ebda4c748aac8b0220192ce28bf9f2c06a6467e6531e27648d2b3e2e2bae85159c9242939840295ba501ffffffff1671efcd750af1809d440af1a8eebc7b48b93be47c85a0c426d06ade38f33a7e4a493046022100b7a1a755588d4190118936e15cd217d133b0e4a53c3c15924010d5648d8925c9022100aaef031874db2114f2d869ac2de4ae53908fbfea5b2b1862e181626bb9005c9f01ffffffff0200e1f505000000004341044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac00180d8f000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00000000"),
    };
    stream >> TX_WITH_WITNESS(block);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the first transaction
    filter.insert(COutPoint(uint256S("0xcf05fd74ebac7edc1d212437fc746f75cf866b38b16accbd672336c326f82a90")));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    std::pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x6da51b59f66af1633d2476f07491891dd8bb20c02fab3d7c2f29d2e8699abd0a"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Match an output from the second transaction (the pubkey for address 1DZTzaBHUDM7T3QvUKBz4qXMRpkg8jsfB5)
    // This should match the third transaction because it spends the output matched
    // It also matches the fourth transaction, which spends to the pubkey again
    filter.insert(ParseHex("044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45af"));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 4);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1].second == uint256S("0xf599cb36e15ef735cf211a8d846166957840f4948180c71df1265fdd50191aa2"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[1].first == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[2].second == uint256S("0x5dfa3c8346b301b5cb4a5d7b61fcc9460760c565872090ac5dcf9df9db459750"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].first == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[3].second == uint256S("0x59c9c5d5ceb26ed87c5b5ae3b7f93c242b5e2af3e7e66e4b19d714baa873f6c0"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[3].first == 3);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_2_with_update_none)
{
    // Random real block (000000005a4ded781e667e06ceefafb71410b511fe0d5adc3e5a27ecbec34ae6)
    // With 4 txes
    CBlock block;
    DataStream stream{
        ParseHex("0100000075616236cc2126035fadb38deb65b9102cc2c41c09cdf29fc0519068000000006c5d6d366b2d42ad68bffce9b63ddf4996a571eba52425a238c58de8048fb43bd4d26e49ffff001d00f0a44104010000000100000000000000000000000000000000000000000000000000000000000000000804ffff001d029105ffffffff0100f2052a010000004341046d8709a041d34357697dfcb30a9d05900a6294078012bf3bb09c6f9b525f1d16d5503d7905db1ada9501446ea00728668fc5719aa80be2fdfc8a858a4dbdd4fbac00000000010000000255605dc6f5c3dc148b6da58442b0b2cd422be385eab2ebea4119ee9c268d283549483045022100aa46504baa86df8a33b1192b1b9367b4d729dc41e389f2c04f3e5c7f0559aae702205e82253a54bf5c4f65b7428551554b2045167d6d206dfe6a2e198127d3f7df1501ffffffff55605dc6f5c3dc148b6da58442b0b2cd422be385eab2ebea4119ee9c268d28354847304402202329484c35fa9d6bb32a55a70c0982f606ce0e3634b69006138683bcd12cbb6602200c28feb1e2555c3210f1dddb299738b4ff8bbe9667b68cb8764b5ac17b7adf0001ffffffff0200e1f505000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00180d8f000000004341044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac000000000100000002add5876bbe324adf5aea9b1f4b08983758f7e039cb23f5c252ec066ed82545484847304402205d6058484157235b06028c30736c15613a28bdb768ee628094ca8b0030d4d6eb0220328789c9a2ec27ddaec0ad5ef58efded42e6ea17c2e1ce838f3d6913f5e95db601ffffffff3be5674f2fcb7ee8f80731e41d37080ae8ad82a1a651f69a7b0db107dd6be4844a493046022100c45af050d3cea806cedd0ab22520c53ebe63b987b8954146cdca42487b84bdd6022100b9b027716a6b59e640da50a864d6dd8a0ef24c76ce62391fa3eabaf4d2886d2d01ffffffff0200e1f505000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00180d8f000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac000000000100000002add5876bbe324adf5aea9b1f4b08983758f7e039cb23f5c252ec066ed825454848473044022016e7a727a061ea2254a6c358376aaa617ac537eb836c77d646ebda4c748aac8b0220192ce28bf9f2c06a6467e6531e27648d2b3e2e2bae85159c9242939840295ba501ffffffff1671efcd750af1809d440af1a8eebc7b48b93be47c85a0c426d06ade38f33a7e4a493046022100b7a1a755588d4190118936e15cd217d133b0e4a53c3c15924010d5648d8925c9022100aaef031874db2114f2d869ac2de4ae53908fbfea5b2b1862e181626bb9005c9f01ffffffff0200e1f505000000004341044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45afac00180d8f000000004341046a0765b5865641ce08dd39690aade26dfbf5511430ca428a3089261361cef170e3929a68aee3d8d4848b0c5111b0a37b82b86ad559fd2a745b44d8e8d9dfdc0cac00000000"),
    };
    stream >> TX_WITH_WITNESS(block);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the first transaction
    filter.insert(COutPoint(uint256S("0xcf05fd74ebac7edc1d212437fc746f75cf866b38b16accbd672336c326f82a90")));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    std::pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x6da51b59f66af1633d2476f07491891dd8bb20c02fab3d7c2f29d2e8699abd0a"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Match an output from the second transaction (the pubkey for address 1DZTzaBHUDM7T3QvUKBz4qXMRpkg8jsfB5)
    // This should not match the third transaction though it spends the output matched
    // It will match the fourth transaction, which has another pay-to-pubkey output to the same address
    filter.insert(ParseHex("044a656f065871a353f216ca26cef8dde2f03e8c16202d2e8ad769f02032cb86a5eb5e56842e92e19141d60a01928f8dd2c875a390f67c1f6c94cfc617c0ea45af"));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 3);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1].second == uint256S("0xf599cb36e15ef735cf211a8d846166957840f4948180c71df1265fdd50191aa2"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[1].first == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[2].second == uint256S("0x59c9c5d5ceb26ed87c5b5ae3b7f93c242b5e2af3e7e66e4b19d714baa873f6c0"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].first == 3);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_3_and_serialize)
{
    // Random real block (000000000000dab0130bbcc991d3d7ae6b81aa6f50a798888dfe62337458dc45)
    // With one tx
    CBlock block;
    DataStream stream{
        ParseHex("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000fba20e4ba5e3198ed1203e7bdf83bf9a658380e69f303e991fb271210cd0c62767291b4d4c86041b8fa45d63010100000001000000000000000000000000000000000000000000000000000000000000000008044c86041b020a02ffffffff0100f2052a01000000434104ecd3229b0571c3be876feaac0442a9f13c5a572742927af1dc623353ecf8c202225f64868137a18cdd85cbbb4c74fbccfd4f49639cf1bdc94a5672bb15ad5d4cac00000000"),
    };
    stream >> TX_WITH_WITNESS(block);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the only transaction
    filter.insert(COutPoint(uint256S("0x002fef0935529226b2b60b79b563962ed91ec94dee7c17fb6b6586d3368fa5a8")));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x27c6d00c2171b21f993e309fe68083659abf83df7b3e20d18e19e3a54b0ea2fb"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    DataStream merkleStream{};
    merkleStream << merkleBlock;

    std::vector<uint8_t> expected = ParseHex("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000fba20e4ba5e3198ed1203e7bdf83bf9a658380e69f303e991fb271210cd0c62767291b4d4c86041b8fa45d630100000001fba20e4ba5e3198ed1203e7bdf83bf9a658380e69f303e991fb271210cd0c6270101");
    auto result{MakeUCharSpan(merkleStream)};

    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(), result.begin(), result.end());
}

BOOST_AUTO_TEST_CASE(merkle_block_4)
{
    // Random real block (000000000000b731f2eef9e8c63173adfb07e41bd53eb0ef0a6b720d6cb6dea4)
    // With 7 txes
    CBlock block;
    DataStream stream{
        ParseHex("0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc8806701000000000017978636849c5aa09ff82257b83a404ee6c2cd83f0c5e1125cd980d35966802076381b4d4c86041b554b8529070100000001000000000000000000000000000000000000000000000000000000000000000007044c86041b0136ffffffff0100f2052a01000000434104eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91ac000000000100000001bcad20a6a29827d1424f08989255120bf7f3e9e3cdaaa6bb31b0737fe0487243494830450220356e834b046cadc0f8ebb5a8a017b02de59c86305403dad52cd77b55af062ea10221009253cd6c119d4729b77c978e1e2aa19f5ea6e0e52b3f16e32fa608cd5bab753901ffffffff02008d380c010000001976a9142b4b8072ecbba129b6453c63e129e643207249ca88ac0065cd1d000000001976a9141b8dd13b994bcfc787b32aeadf58ccb3615cbd5488ac0000000001000000037db81e282219f11e82fe763a1ba6daf84d7396cb44facf9057ed0c710a2daa008c493046022100ea1608e70911ca0de5af51ba57ad23b9a51db8d28f82c53563c56a05c20f5a87022100a8bdc8b4a8acc8634c6b420410150775eb7f2474f5615f7fccd65af30f310fbf01410465fdf49e29b06b9a1582287b6279014f834edc317695d125ef623c1cc3aaece245bd69fcad7508666e9c74a49dc9056d5fc14338ef38118dc4afae5fe2c585caffffffff309e1913634ecb50f3c4f83e96e70b2df071b497b8973a3e75429df397b5af834948304502202bdb79c596a9ffc24e96f4386199aba386e9bc7b6071516e2b51dda942b3a1ed022100c53a857e76b724fc14d45311eac5019650d415c3abb5428f3aae16d8e69bec2301ffffffff2089e33491695080c9edc18a428f7d834db5b6d372df13ce2b1b0e0cbcb1e6c149483045022100d4ce67c5896ee251c810ac1ff9ceccd328b497c8f553ab6e08431e7d40bad6b5022033119c0c2b7d792d31f1187779c7bd95aefd93d90a715586d73801d9b47471c601ffffffff0100714460030000001976a914c7b55141d097ea5df7a0ed330cf794376e53ec8d88ac0000000001000000045bf0e214aa4069a3e792ecee1e1bf0c1d397cde8dd08138f4b72a006817434478b48304502200c45de8c4f3e2c1821f2fc878cba97b1e6f8807d94930713aa1c86a67b9bf1e40221008581abfef2e30f957815fc89978423746b2086375ca8ecf359c85c2a5b7c88ad01410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffffd669f7d7958d40fc59d2253d88e0f248e29b599c80bbcec344a83dda5f9aa72c8a473044022078124c8beeaa825f9e0b30bff96e564dd859432f2d0cb3b72d3d5d93d38d7e930220691d233b6c0f995be5acb03d70a7f7a65b6bc9bdd426260f38a1346669507a3601410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95fffffffff878af0d93f5229a68166cf051fd372bb7a537232946e0a46f53636b4dafdaa48c493046022100c717d1714551663f69c3c5759bdbb3a0fcd3fab023abc0e522fe6440de35d8290221008d9cbe25bffc44af2b18e81c58eb37293fd7fe1c2e7b46fc37ee8c96c50ab1e201410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff27f2b668859cd7f2f894aa0fd2d9e60963bcd07c88973f425f999b8cbfd7a1e28c493046022100e00847147cbf517bcc2f502f3ddc6d284358d102ed20d47a8aa788a62f0db780022100d17b2d6fa84dcaf1c95d88d7e7c30385aecf415588d749afd3ec81f6022cecd701410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff0100c817a8040000001976a914b6efd80d99179f4f4ff6f4dd0a007d018c385d2188ac000000000100000001834537b2f1ce8ef9373a258e10545ce5a50b758df616cd4356e0032554ebd3c48b483045022100e68f422dd7c34fdce11eeb4509ddae38201773dd62f284e8aa9d96f85099d0b002202243bd399ff96b649a0fad05fa759d6a882f0af8c90cf7632c2840c29070aec20141045e58067e815c2f464c6a2a15f987758374203895710c2d452442e28496ff38ba8f5fd901dc20e29e88477167fe4fc299bf818fd0d9e1632d467b2a3d9503b1aaffffffff0280d7e636030000001976a914f34c3e10eb387efe872acb614c89e78bfca7815d88ac404b4c00000000001976a914a84e272933aaf87e1715d7786c51dfaeb5b65a6f88ac00000000010000000143ac81c8e6f6ef307dfe17f3d906d999e23e0189fda838c5510d850927e03ae78c4930460221009c87c344760a64cb8ae6685a3eec2c1ac1bed5b88c87de51acd0e124f266c16602210082d07c037359c3a257b5c63ebd90f5a5edf97b2ac1c434b08ca998839f346dd40141040ba7e521fa7946d12edbb1d1e95a15c34bd4398195e86433c92b431cd315f455fe30032ede69cad9d1e1ed6c3c4ec0dbfced53438c625462afb792dcb098544bffffffff0240420f00000000001976a9144676d1b820d63ec272f1900d59d43bc6463d96f888ac40420f00000000001976a914648d04341d00d7968b3405c034adc38d4d8fb9bd88ac00000000010000000248cc917501ea5c55f4a8d2009c0567c40cfe037c2e71af017d0a452ff705e3f18b483045022100bf5fdc86dc5f08a5d5c8e43a8c9d5b1ed8c65562e280007b52b133021acd9acc02205e325d613e555f772802bf413d36ba807892ed1a690a77811d3033b3de226e0a01410429fa713b124484cb2bd7b5557b2c0b9df7b2b1fee61825eadc5ae6c37a9920d38bfccdc7dc3cb0c47d7b173dbc9db8d37db0a33ae487982c59c6f8606e9d1791ffffffffdb2694a449a448f7c11043b616522c449e7950fcacacbbd0b4e28994b308bb7c8b4830450221008513ad65187b903aed1102d1d0c47688127658c51106753fed0151ce9c16b80902201432b9ebcb87bd04ceb2de66035fbbaf4bf8b00d1cfe41f1a1f7338f9ad79d210141049d4cf80125bf50be1709f718c07ad15d0fc612b7da1f5570dddc35f2a352f0f27c978b06820edca9ef982c35fda2d255afba340068c5035552368bc7200c1488ffffffff0100093d00000000001976a9148edb68822f1ad580b043c7b3df2e400f8699eb4888ac00000000"),
    };
    stream >> TX_WITH_WITNESS(block);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the last transaction
    filter.insert(COutPoint(uint256S("0x0e404094a254bb9331ba518be4811017c7b6c4221fd82812876651a00706f36e")));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    std::pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x97e7f91ce31211ac63f182cd2154d2b8aa575689fe925f43077514a608a9dca0"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 6);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Also match the 4th transaction
    filter.insert(COutPoint(uint256S("0x98b059dffd2b8a3e14f1a943384cebb96a002fa4250b169a733419d9b9381c93")));
    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0xb521c43b01a9cbf679dac8ea79fb9be5683ce2eb1e0cb284d14b37f3d5e948ef"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 3);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1] == pair);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_p2pubkey_only)
{
    // Random real block (000000000000b731f2eef9e8c63173adfb07e41bd53eb0ef0a6b720d6cb6dea4)
    // With 7 txes
    CBlock block;
    DataStream stream{
        ParseHex("0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc8806701000000000017978636849c5aa09ff82257b83a404ee6c2cd83f0c5e1125cd980d35966802076381b4d4c86041b554b8529070100000001000000000000000000000000000000000000000000000000000000000000000007044c86041b0136ffffffff0100f2052a01000000434104eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91ac000000000100000001bcad20a6a29827d1424f08989255120bf7f3e9e3cdaaa6bb31b0737fe0487243494830450220356e834b046cadc0f8ebb5a8a017b02de59c86305403dad52cd77b55af062ea10221009253cd6c119d4729b77c978e1e2aa19f5ea6e0e52b3f16e32fa608cd5bab753901ffffffff02008d380c010000001976a9142b4b8072ecbba129b6453c63e129e643207249ca88ac0065cd1d000000001976a9141b8dd13b994bcfc787b32aeadf58ccb3615cbd5488ac0000000001000000037db81e282219f11e82fe763a1ba6daf84d7396cb44facf9057ed0c710a2daa008c493046022100ea1608e70911ca0de5af51ba57ad23b9a51db8d28f82c53563c56a05c20f5a87022100a8bdc8b4a8acc8634c6b420410150775eb7f2474f5615f7fccd65af30f310fbf01410465fdf49e29b06b9a1582287b6279014f834edc317695d125ef623c1cc3aaece245bd69fcad7508666e9c74a49dc9056d5fc14338ef38118dc4afae5fe2c585caffffffff309e1913634ecb50f3c4f83e96e70b2df071b497b8973a3e75429df397b5af834948304502202bdb79c596a9ffc24e96f4386199aba386e9bc7b6071516e2b51dda942b3a1ed022100c53a857e76b724fc14d45311eac5019650d415c3abb5428f3aae16d8e69bec2301ffffffff2089e33491695080c9edc18a428f7d834db5b6d372df13ce2b1b0e0cbcb1e6c149483045022100d4ce67c5896ee251c810ac1ff9ceccd328b497c8f553ab6e08431e7d40bad6b5022033119c0c2b7d792d31f1187779c7bd95aefd93d90a715586d73801d9b47471c601ffffffff0100714460030000001976a914c7b55141d097ea5df7a0ed330cf794376e53ec8d88ac0000000001000000045bf0e214aa4069a3e792ecee1e1bf0c1d397cde8dd08138f4b72a006817434478b48304502200c45de8c4f3e2c1821f2fc878cba97b1e6f8807d94930713aa1c86a67b9bf1e40221008581abfef2e30f957815fc89978423746b2086375ca8ecf359c85c2a5b7c88ad01410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffffd669f7d7958d40fc59d2253d88e0f248e29b599c80bbcec344a83dda5f9aa72c8a473044022078124c8beeaa825f9e0b30bff96e564dd859432f2d0cb3b72d3d5d93d38d7e930220691d233b6c0f995be5acb03d70a7f7a65b6bc9bdd426260f38a1346669507a3601410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95fffffffff878af0d93f5229a68166cf051fd372bb7a537232946e0a46f53636b4dafdaa48c493046022100c717d1714551663f69c3c5759bdbb3a0fcd3fab023abc0e522fe6440de35d8290221008d9cbe25bffc44af2b18e81c58eb37293fd7fe1c2e7b46fc37ee8c96c50ab1e201410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff27f2b668859cd7f2f894aa0fd2d9e60963bcd07c88973f425f999b8cbfd7a1e28c493046022100e00847147cbf517bcc2f502f3ddc6d284358d102ed20d47a8aa788a62f0db780022100d17b2d6fa84dcaf1c95d88d7e7c30385aecf415588d749afd3ec81f6022cecd701410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff0100c817a8040000001976a914b6efd80d99179f4f4ff6f4dd0a007d018c385d2188ac000000000100000001834537b2f1ce8ef9373a258e10545ce5a50b758df616cd4356e0032554ebd3c48b483045022100e68f422dd7c34fdce11eeb4509ddae38201773dd62f284e8aa9d96f85099d0b002202243bd399ff96b649a0fad05fa759d6a882f0af8c90cf7632c2840c29070aec20141045e58067e815c2f464c6a2a15f987758374203895710c2d452442e28496ff38ba8f5fd901dc20e29e88477167fe4fc299bf818fd0d9e1632d467b2a3d9503b1aaffffffff0280d7e636030000001976a914f34c3e10eb387efe872acb614c89e78bfca7815d88ac404b4c00000000001976a914a84e272933aaf87e1715d7786c51dfaeb5b65a6f88ac00000000010000000143ac81c8e6f6ef307dfe17f3d906d999e23e0189fda838c5510d850927e03ae78c4930460221009c87c344760a64cb8ae6685a3eec2c1ac1bed5b88c87de51acd0e124f266c16602210082d07c037359c3a257b5c63ebd90f5a5edf97b2ac1c434b08ca998839f346dd40141040ba7e521fa7946d12edbb1d1e95a15c34bd4398195e86433c92b431cd315f455fe30032ede69cad9d1e1ed6c3c4ec0dbfced53438c625462afb792dcb098544bffffffff0240420f00000000001976a9144676d1b820d63ec272f1900d59d43bc6463d96f888ac40420f00000000001976a914648d04341d00d7968b3405c034adc38d4d8fb9bd88ac00000000010000000248cc917501ea5c55f4a8d2009c0567c40cfe037c2e71af017d0a452ff705e3f18b483045022100bf5fdc86dc5f08a5d5c8e43a8c9d5b1ed8c65562e280007b52b133021acd9acc02205e325d613e555f772802bf413d36ba807892ed1a690a77811d3033b3de226e0a01410429fa713b124484cb2bd7b5557b2c0b9df7b2b1fee61825eadc5ae6c37a9920d38bfccdc7dc3cb0c47d7b173dbc9db8d37db0a33ae487982c59c6f8606e9d1791ffffffffdb2694a449a448f7c11043b616522c449e7950fcacacbbd0b4e28994b308bb7c8b4830450221008513ad65187b903aed1102d1d0c47688127658c51106753fed0151ce9c16b80902201432b9ebcb87bd04ceb2de66035fbbaf4bf8b00d1cfe41f1a1f7338f9ad79d210141049d4cf80125bf50be1709f718c07ad15d0fc612b7da1f5570dddc35f2a352f0f27c978b06820edca9ef982c35fda2d255afba340068c5035552368bc7200c1488ffffffff0100093d00000000001976a9148edb68822f1ad580b043c7b3df2e400f8699eb4888ac00000000"),
    };
    stream >> TX_WITH_WITNESS(block);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_P2PUBKEY_ONLY);
    // Match the generation pubkey
    filter.insert(ParseHex("04eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91"));
    // ...and the output address of the 4th transaction
    filter.insert(ParseHex("b6efd80d99179f4f4ff6f4dd0a007d018c385d21"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    // ... but not the 4th transaction's output (its not pay-2-pubkey)
    BOOST_CHECK(!filter.contains(COutPoint(TxidFromString("0xb521c43b01a9cbf679dac8ea79fb9be5683ce2eb1e0cb284d14b37f3d5e948ef"))));
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_update_none)
{
    // Random real block (000000000000b731f2eef9e8c63173adfb07e41bd53eb0ef0a6b720d6cb6dea4)
    // With 7 txes
    CBlock block;
    DataStream stream{
        ParseHex("0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc8806701000000000017978636849c5aa09ff82257b83a404ee6c2cd83f0c5e1125cd980d35966802076381b4d4c86041b554b8529070100000001000000000000000000000000000000000000000000000000000000000000000007044c86041b0136ffffffff0100f2052a01000000434104eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91ac000000000100000001bcad20a6a29827d1424f08989255120bf7f3e9e3cdaaa6bb31b0737fe0487243494830450220356e834b046cadc0f8ebb5a8a017b02de59c86305403dad52cd77b55af062ea10221009253cd6c119d4729b77c978e1e2aa19f5ea6e0e52b3f16e32fa608cd5bab753901ffffffff02008d380c010000001976a9142b4b8072ecbba129b6453c63e129e643207249ca88ac0065cd1d000000001976a9141b8dd13b994bcfc787b32aeadf58ccb3615cbd5488ac0000000001000000037db81e282219f11e82fe763a1ba6daf84d7396cb44facf9057ed0c710a2daa008c493046022100ea1608e70911ca0de5af51ba57ad23b9a51db8d28f82c53563c56a05c20f5a87022100a8bdc8b4a8acc8634c6b420410150775eb7f2474f5615f7fccd65af30f310fbf01410465fdf49e29b06b9a1582287b6279014f834edc317695d125ef623c1cc3aaece245bd69fcad7508666e9c74a49dc9056d5fc14338ef38118dc4afae5fe2c585caffffffff309e1913634ecb50f3c4f83e96e70b2df071b497b8973a3e75429df397b5af834948304502202bdb79c596a9ffc24e96f4386199aba386e9bc7b6071516e2b51dda942b3a1ed022100c53a857e76b724fc14d45311eac5019650d415c3abb5428f3aae16d8e69bec2301ffffffff2089e33491695080c9edc18a428f7d834db5b6d372df13ce2b1b0e0cbcb1e6c149483045022100d4ce67c5896ee251c810ac1ff9ceccd328b497c8f553ab6e08431e7d40bad6b5022033119c0c2b7d792d31f1187779c7bd95aefd93d90a715586d73801d9b47471c601ffffffff0100714460030000001976a914c7b55141d097ea5df7a0ed330cf794376e53ec8d88ac0000000001000000045bf0e214aa4069a3e792ecee1e1bf0c1d397cde8dd08138f4b72a006817434478b48304502200c45de8c4f3e2c1821f2fc878cba97b1e6f8807d94930713aa1c86a67b9bf1e40221008581abfef2e30f957815fc89978423746b2086375ca8ecf359c85c2a5b7c88ad01410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffffd669f7d7958d40fc59d2253d88e0f248e29b599c80bbcec344a83dda5f9aa72c8a473044022078124c8beeaa825f9e0b30bff96e564dd859432f2d0cb3b72d3d5d93d38d7e930220691d233b6c0f995be5acb03d70a7f7a65b6bc9bdd426260f38a1346669507a3601410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95fffffffff878af0d93f5229a68166cf051fd372bb7a537232946e0a46f53636b4dafdaa48c493046022100c717d1714551663f69c3c5759bdbb3a0fcd3fab023abc0e522fe6440de35d8290221008d9cbe25bffc44af2b18e81c58eb37293fd7fe1c2e7b46fc37ee8c96c50ab1e201410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff27f2b668859cd7f2f894aa0fd2d9e60963bcd07c88973f425f999b8cbfd7a1e28c493046022100e00847147cbf517bcc2f502f3ddc6d284358d102ed20d47a8aa788a62f0db780022100d17b2d6fa84dcaf1c95d88d7e7c30385aecf415588d749afd3ec81f6022cecd701410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff0100c817a8040000001976a914b6efd80d99179f4f4ff6f4dd0a007d018c385d2188ac000000000100000001834537b2f1ce8ef9373a258e10545ce5a50b758df616cd4356e0032554ebd3c48b483045022100e68f422dd7c34fdce11eeb4509ddae38201773dd62f284e8aa9d96f85099d0b002202243bd399ff96b649a0fad05fa759d6a882f0af8c90cf7632c2840c29070aec20141045e58067e815c2f464c6a2a15f987758374203895710c2d452442e28496ff38ba8f5fd901dc20e29e88477167fe4fc299bf818fd0d9e1632d467b2a3d9503b1aaffffffff0280d7e636030000001976a914f34c3e10eb387efe872acb614c89e78bfca7815d88ac404b4c00000000001976a914a84e272933aaf87e1715d7786c51dfaeb5b65a6f88ac00000000010000000143ac81c8e6f6ef307dfe17f3d906d999e23e0189fda838c5510d850927e03ae78c4930460221009c87c344760a64cb8ae6685a3eec2c1ac1bed5b88c87de51acd0e124f266c16602210082d07c037359c3a257b5c63ebd90f5a5edf97b2ac1c434b08ca998839f346dd40141040ba7e521fa7946d12edbb1d1e95a15c34bd4398195e86433c92b431cd315f455fe30032ede69cad9d1e1ed6c3c4ec0dbfced53438c625462afb792dcb098544bffffffff0240420f00000000001976a9144676d1b820d63ec272f1900d59d43bc6463d96f888ac40420f00000000001976a914648d04341d00d7968b3405c034adc38d4d8fb9bd88ac00000000010000000248cc917501ea5c55f4a8d2009c0567c40cfe037c2e71af017d0a452ff705e3f18b483045022100bf5fdc86dc5f08a5d5c8e43a8c9d5b1ed8c65562e280007b52b133021acd9acc02205e325d613e555f772802bf413d36ba807892ed1a690a77811d3033b3de226e0a01410429fa713b124484cb2bd7b5557b2c0b9df7b2b1fee61825eadc5ae6c37a9920d38bfccdc7dc3cb0c47d7b173dbc9db8d37db0a33ae487982c59c6f8606e9d1791ffffffffdb2694a449a448f7c11043b616522c449e7950fcacacbbd0b4e28994b308bb7c8b4830450221008513ad65187b903aed1102d1d0c47688127658c51106753fed0151ce9c16b80902201432b9ebcb87bd04ceb2de66035fbbaf4bf8b00d1cfe41f1a1f7338f9ad79d210141049d4cf80125bf50be1709f718c07ad15d0fc612b7da1f5570dddc35f2a352f0f27c978b06820edca9ef982c35fda2d255afba340068c5035552368bc7200c1488ffffffff0100093d00000000001976a9148edb68822f1ad580b043c7b3df2e400f8699eb4888ac00000000"),
    };
    stream >> TX_WITH_WITNESS(block);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the generation pubkey
    filter.insert(ParseHex("04eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91"));
    // ...and the output address of the 4th transaction
    filter.insert(ParseHex("b6efd80d99179f4f4ff6f4dd0a007d018c385d21"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    // We shouldn't match any outpoints (UPDATE_NONE)
    BOOST_CHECK(!filter.contains(COutPoint(TxidFromString("0x87f527c48f5b34c6b8fb6855da63b337063456f0311e307eda30f63356536d90"))));
    BOOST_CHECK(!filter.contains(COutPoint(TxidFromString("0xb521c43b01a9cbf679dac8ea79fb9be5683ce2eb1e0cb284d14b37f3d5e948ef"))));
}

static std::vector<unsigned char> RandomData()
{
    uint256 r = InsecureRand256();
    return std::vector<unsigned char>(r.begin(), r.end());
}

BOOST_AUTO_TEST_CASE(rolling_bloom)
{
    SeedInsecureRand(SeedRand::ZEROS);
    g_mock_deterministic_tests = true;

    // last-100-entry, 1% false positive:
    CRollingBloomFilter rb1(100, 0.01);

    // Overfill:
    static const int DATASIZE=399;
    std::vector<unsigned char> data[DATASIZE];
    for (int i = 0; i < DATASIZE; i++) {
        data[i] = RandomData();
        rb1.insert(data[i]);
    }
    // Last 100 guaranteed to be remembered:
    for (int i = 299; i < DATASIZE; i++) {
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // false positive rate is 1%, so we should get about 100 hits if
    // testing 10,000 random keys. We get worst-case false positive
    // behavior when the filter is as full as possible, which is
    // when we've inserted one minus an integer multiple of nElement*2.
    unsigned int nHits = 0;
    for (int i = 0; i < 10000; i++) {
        if (rb1.contains(RandomData()))
            ++nHits;
    }
    // Expect about 100 hits
    BOOST_CHECK_EQUAL(nHits, 75U);

    BOOST_CHECK(rb1.contains(data[DATASIZE-1]));
    rb1.reset();
    BOOST_CHECK(!rb1.contains(data[DATASIZE-1]));

    // Now roll through data, make sure last 100 entries
    // are always remembered:
    for (int i = 0; i < DATASIZE; i++) {
        if (i >= 100)
            BOOST_CHECK(rb1.contains(data[i-100]));
        rb1.insert(data[i]);
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // Insert 999 more random entries:
    for (int i = 0; i < 999; i++) {
        std::vector<unsigned char> d = RandomData();
        rb1.insert(d);
        BOOST_CHECK(rb1.contains(d));
    }
    // Sanity check to make sure the filter isn't just filling up:
    nHits = 0;
    for (int i = 0; i < DATASIZE; i++) {
        if (rb1.contains(data[i]))
            ++nHits;
    }
    // Expect about 5 false positives
    BOOST_CHECK_EQUAL(nHits, 6U);

    // last-1000-entry, 0.01% false positive:
    CRollingBloomFilter rb2(1000, 0.001);
    for (int i = 0; i < DATASIZE; i++) {
        rb2.insert(data[i]);
    }
    // ... room for all of them:
    for (int i = 0; i < DATASIZE; i++) {
        BOOST_CHECK(rb2.contains(data[i]));
    }
    g_mock_deterministic_tests = false;
}

BOOST_AUTO_TEST_SUITE_END()
