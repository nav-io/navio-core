// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/blst/blst.h>
#include <chainparams.h>
#include <coins.h>
#include <crypto/muhash.h>
#include <index/coinstatsindex.h>
#include <interfaces/chain.h>
#include <kernel/coinstats.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/index.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(coinstatsindex_tests)

BOOST_FIXTURE_TEST_CASE(coinstatsindex_initial_sync, TestChain100Setup)
{
    CoinStatsIndex coin_stats_index{interfaces::MakeChain(m_node), 1 << 20, true};
    BOOST_REQUIRE(coin_stats_index.Init());

    const CBlockIndex* block_index;
    {
        LOCK(cs_main);
        block_index = m_node.chainman->ActiveChain().Tip();
    }

    // CoinStatsIndex should not be found before it is started.
    BOOST_CHECK(!coin_stats_index.LookUpStats(*block_index));

    // BlockUntilSyncedToCurrentChain should return false before CoinStatsIndex
    // is started.
    BOOST_CHECK(!coin_stats_index.BlockUntilSyncedToCurrentChain());

    BOOST_REQUIRE(coin_stats_index.StartBackgroundSync());

    IndexWaitSynced(coin_stats_index, *Assert(m_node.shutdown));

    // Check that CoinStatsIndex works for genesis block.
    const CBlockIndex* genesis_block_index;
    {
        LOCK(cs_main);
        genesis_block_index = m_node.chainman->ActiveChain().Genesis();
    }
    BOOST_CHECK(coin_stats_index.LookUpStats(*genesis_block_index));

    // Check that CoinStatsIndex updates with new blocks.
    BOOST_CHECK(coin_stats_index.LookUpStats(*block_index));

    const CScript script_pub_key{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    std::vector<CMutableTransaction> noTxns;
    CreateAndProcessBlock(noTxns, script_pub_key);

    // Let the CoinStatsIndex to catch up again.
    BOOST_CHECK(coin_stats_index.BlockUntilSyncedToCurrentChain());

    const CBlockIndex* new_block_index;
    {
        LOCK(cs_main);
        new_block_index = m_node.chainman->ActiveChain().Tip();
    }
    BOOST_CHECK(coin_stats_index.LookUpStats(*new_block_index));

    BOOST_CHECK(block_index != new_block_index);

    // It is not safe to stop and destroy the index until it finishes handling
    // the last BlockConnected notification. The BlockUntilSyncedToCurrentChain()
    // call above is sufficient to ensure this, but the
    // SyncWithValidationInterfaceQueue() call below is also needed to ensure
    // TSAN always sees the test thread waiting for the notification thread, and
    // avoid potential false positive reports.
    SyncWithValidationInterfaceQueue();

    // Shutdown sequence (c.f. Shutdown() in init.cpp)
    coin_stats_index.Stop();
}

// Test shutdown between BlockConnected and ChainStateFlushed notifications,
// make sure index is not corrupted and is able to reload.
BOOST_FIXTURE_TEST_CASE(coinstatsindex_unclean_shutdown, TestChain100Setup)
{
    Chainstate& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    const CChainParams& params = Params();
    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        BOOST_REQUIRE(index.Init());
        BOOST_REQUIRE(index.StartBackgroundSync());
        IndexWaitSynced(index, *Assert(m_node.shutdown));
        std::shared_ptr<const CBlock> new_block;
        CBlockIndex* new_block_index = nullptr;
        {
            const CScript script_pub_key{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
            const CBlock block = this->CreateBlock({}, script_pub_key, chainstate);

            new_block = std::make_shared<CBlock>(block);

            LOCK(cs_main);
            BlockValidationState state;
            BOOST_CHECK(CheckBlock(block, state, params.GetConsensus()));
            BOOST_CHECK(m_node.chainman->AcceptBlock(new_block, state, &new_block_index, true, nullptr, nullptr, true));
            CCoinsViewCache view(&chainstate.CoinsTip());
            BOOST_CHECK(chainstate.ConnectBlock(block, state, new_block_index, view));
        }
        // Send block connected notification, then stop the index without
        // sending a chainstate flushed notification. Prior to #24138, this
        // would cause the index to be corrupted and fail to reload.
        ValidationInterfaceTest::BlockConnected(ChainstateRole::NORMAL, index, new_block, new_block_index);
        index.Stop();
    }

    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        BOOST_REQUIRE(index.Init());
        // Make sure the index can be loaded.
        BOOST_REQUIRE(index.StartBackgroundSync());
        index.Stop();
    }
}

BOOST_FIXTURE_TEST_CASE(coin_hash_canonical_blsct, BasicTestingSetup)
{
    // A BLSCT output with a populated range proof, as it appears in a block.
    CTxOut out;
    out.nValue = 0;
    out.scriptPubKey = CScript() << OP_TRUE;
    out.blsctData.spendingKey = BlstG1Point::Rand();
    out.blsctData.ephemeralKey = BlstG1Point::Rand();
    out.blsctData.blindingKey = BlstG1Point::Rand();
    out.blsctData.viewTag = 42;
    auto& proof = out.blsctData.rangeProof;
    proof.Vs.Add(BlstG1Point::Rand());
    proof.Ls.Add(BlstG1Point::Rand());
    proof.Rs.Add(BlstG1Point::Rand());
    proof.A = BlstG1Point::Rand();
    proof.A_wip = BlstG1Point::Rand();
    proof.B = BlstG1Point::Rand();
    proof.r_prime = BlstScalar::Rand();
    proof.tau_x = BlstScalar::Rand();

    // The coin key is the outid of the full output.
    const COutPoint outpoint{out.GetHash()};
    const Coin block_coin{out, /*nHeightIn=*/7, /*fCoinBaseIn=*/false};

    // The same coin as block-undo data carries it: the range-proof body is
    // dropped on write and left default on read.
    DataStream undo_stream{};
    {
        CTxOutBLSCTData::StrippedForUndoScope strip_scope;
        undo_stream << out;
    }
    CTxOut undo_out;
    {
        CTxOutBLSCTData::StrippedForUndoScope strip_scope;
        undo_stream >> undo_out;
    }
    const Coin undo_coin{undo_out, /*nHeightIn=*/7, /*fCoinBaseIn=*/false};

    // The two shapes really differ, or this test would prove nothing.
    BOOST_CHECK((DataStream{} << block_coin.out).str() != (DataStream{} << undo_coin.out).str());

    uint256 empty_digest;
    MuHash3072{}.Finalize(empty_digest);

    // Created from the block, spent from undo data: the set is empty again.
    MuHash3072 spent;
    kernel::ApplyCoinHash(spent, outpoint, block_coin);
    kernel::RemoveCoinHash(spent, outpoint, undo_coin);
    uint256 spent_digest;
    spent.Finalize(spent_digest);
    BOOST_CHECK_EQUAL(spent_digest, empty_digest);

    // Restored from undo data on disconnect, removed from the block on the
    // next disconnect of the creating block: also cancels.
    MuHash3072 restored;
    kernel::ApplyCoinHash(restored, outpoint, undo_coin);
    kernel::RemoveCoinHash(restored, outpoint, block_coin);
    uint256 restored_digest;
    restored.Finalize(restored_digest);
    BOOST_CHECK_EQUAL(restored_digest, empty_digest);

    // And a UTXO set holding either shape commits to the same value.
    MuHash3072 with_block_coin, with_undo_coin;
    kernel::ApplyCoinHash(with_block_coin, outpoint, block_coin);
    kernel::ApplyCoinHash(with_undo_coin, outpoint, undo_coin);
    uint256 block_digest, undo_digest;
    with_block_coin.Finalize(block_digest);
    with_undo_coin.Finalize(undo_digest);
    BOOST_CHECK_EQUAL(block_digest, undo_digest);
    BOOST_CHECK(block_digest != empty_digest);
}

BOOST_AUTO_TEST_SUITE_END()
