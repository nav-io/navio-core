// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/validation.h>
#include <index/outindex.h>
#include <interfaces/chain.h>
#include <streams.h>
#include <test/util/index.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(outindex_tests)

BOOST_AUTO_TEST_CASE(outindex_entry_serialization)
{
    OutIndexEntry unspent;
    unspent.height = 1234;
    unspent.tx_pos = 7;
    unspent.out_pos = 300;

    OutIndexEntry spent{unspent};
    spent.spent = OutIndexEntry::Spend{5678, 2, 1};

    for (const OutIndexEntry& entry : {unspent, spent}) {
        DataStream ss{};
        ss << entry;
        OutIndexEntry read;
        read.spent = OutIndexEntry::Spend{}; // must be cleared when absent
        ss >> read;
        BOOST_CHECK(read == entry);
        BOOST_CHECK(ss.empty());
    }
}

BOOST_FIXTURE_TEST_CASE(outindex_sync_spend_and_reorg, TestChain100Setup)
{
    OutIndex outindex(interfaces::MakeChain(m_node), 1 << 20, true);
    BOOST_REQUIRE(outindex.Init());

    const uint256 cb_out{m_coinbase_txns[0]->vout[0].GetHash()};

    // Nothing is found before the index has synced.
    BOOST_CHECK(!outindex.FindOutput(cb_out));

    BOOST_REQUIRE(outindex.StartBackgroundSync());
    IndexWaitSynced(outindex, *Assert(m_node.shutdown));

    // Every output that existed before the index started is present, unspent.
    for (size_t i = 0; i < m_coinbase_txns.size(); ++i) {
        const auto entry{outindex.FindOutput(m_coinbase_txns[i]->vout[0].GetHash())};
        BOOST_REQUIRE(entry);
        BOOST_CHECK_EQUAL(entry->height, int(i) + 1);
        BOOST_CHECK_EQUAL(entry->tx_pos, 0U);
        BOOST_CHECK_EQUAL(entry->out_pos, 0U);
        BOOST_CHECK(!entry->spent);
    }

    // Blocks mined below pay their coinbase to a fresh key so that their
    // outputs have ids of their own.
    auto fresh_spk = [] { return GetScriptForDestination(PKHash(GenerateRandomKey().GetPubKey())); };

    // Block A creates output X; block B spends X and creates Y.
    const CKey key_x{GenerateRandomKey()};
    const CMutableTransaction tx_a{CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1, coinbaseKey,
                                                                 GetScriptForDestination(PKHash(key_x.GetPubKey())),
                                                                 CAmount(10 * COIN), /*submit=*/false)};
    CreateAndProcessBlock({tx_a}, fresh_spk());
    const int height_a{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height())};
    const CMutableTransaction tx_b{CreateValidMempoolTransaction(MakeTransactionRef(tx_a), 0, height_a, key_x,
                                                                 fresh_spk(), CAmount(9 * COIN), /*submit=*/false)};
    const CBlock block_b{CreateAndProcessBlock({tx_b}, fresh_spk())};
    const int height_b{height_a + 1};
    BOOST_REQUIRE(outindex.BlockUntilSyncedToCurrentChain());

    const uint256 out_x{CTransaction{tx_a}.vout[0].GetHash()};
    const uint256 out_y{CTransaction{tx_b}.vout[0].GetHash()};

    auto entry{outindex.FindOutput(out_x)};
    BOOST_REQUIRE(entry);
    BOOST_CHECK_EQUAL(entry->height, height_a);
    BOOST_CHECK_EQUAL(entry->tx_pos, 1U);
    BOOST_CHECK_EQUAL(entry->out_pos, 0U);
    BOOST_REQUIRE(entry->spent);
    BOOST_CHECK_EQUAL(entry->spent->height, height_b);
    BOOST_CHECK_EQUAL(entry->spent->tx_pos, 1U);
    BOOST_CHECK_EQUAL(entry->spent->in_pos, 0U);

    entry = outindex.FindOutput(out_y);
    BOOST_REQUIRE(entry);
    BOOST_CHECK_EQUAL(entry->height, height_b);
    BOOST_CHECK_EQUAL(entry->tx_pos, 1U);
    BOOST_CHECK(!entry->spent);

    const uint256 block_b_cb_out{block_b.vtx[0]->vout[0].GetHash()};
    BOOST_CHECK(outindex.FindOutput(block_b_cb_out));

    // Replace block B with two empty blocks. The index rewinds when the
    // replacement connects: the spend of X is cleared and the outputs block B
    // created are gone.
    {
        BlockValidationState state;
        CBlockIndex* tip{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip())};
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip));
    }
    CreateAndProcessBlock({}, fresh_spk());
    CreateAndProcessBlock({}, fresh_spk());
    BOOST_REQUIRE(outindex.BlockUntilSyncedToCurrentChain());

    entry = outindex.FindOutput(out_x);
    BOOST_REQUIRE(entry);
    BOOST_CHECK_EQUAL(entry->height, height_a);
    BOOST_CHECK(!entry->spent);
    BOOST_CHECK(!outindex.FindOutput(out_y));
    BOOST_CHECK(!outindex.FindOutput(block_b_cb_out));

    // Switch back to block B: clear its failure flag and invalidate the
    // replacement branch instead.
    {
        LOCK(cs_main);
        CBlockIndex* original{m_node.chainman->m_blockman.LookupBlockIndex(block_b.GetHash())};
        m_node.chainman->ActiveChainstate().ResetBlockFailureFlags(original);
    }
    {
        BlockValidationState state;
        CBlockIndex* replacement{WITH_LOCK(cs_main, return m_node.chainman->ActiveChain()[height_b])};
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, replacement));
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().ActivateBestChain(state));
    }
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash()), block_b.GetHash());
    BOOST_REQUIRE(outindex.BlockUntilSyncedToCurrentChain());

    entry = outindex.FindOutput(out_x);
    BOOST_REQUIRE(entry);
    BOOST_REQUIRE(entry->spent);
    BOOST_CHECK_EQUAL(entry->spent->height, height_b);
    entry = outindex.FindOutput(out_y);
    BOOST_REQUIRE(entry);
    BOOST_CHECK_EQUAL(entry->height, height_b);

    // See txindex_tests for why this is needed before stopping the index.
    SyncWithValidationInterfaceQueue();
    outindex.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
