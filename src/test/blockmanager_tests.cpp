// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/blst/blst.h>
#include <chainparams.h>
#include <clientversion.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <script/solver.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <undo.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <test/util/threads.h>

using node::BLOCK_SERIALIZATION_HEADER_SIZE;
using node::BlockManager;
using node::KernelNotifications;
using node::MAX_BLOCKFILE_SIZE;
using node::UNDO_WRITE_MIN_ENTRIES_PER_THREAD;

// use BasicTestingSetup here for the data directory configuration, setup, and cleanup
BOOST_FIXTURE_TEST_SUITE(blockmanager_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(blockmanager_find_block_pos)
{
    const auto params {CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{*Assert(m_node.shutdown), m_node.exit_status};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
    };
    BlockManager blockman{*Assert(m_node.shutdown), blockman_opts};
    // simulate adding a genesis block normally
    BOOST_CHECK_EQUAL(blockman.SaveBlockToDisk(params->GenesisBlock(), 0, nullptr).nPos, BLOCK_SERIALIZATION_HEADER_SIZE);
    // simulate what happens during reindex
    // simulate a well-formed genesis block being found at offset 8 in the blk00000.dat file
    // the block is found at offset 8 because there is an 8 byte serialization header
    // consisting of 4 magic bytes + 4 length bytes before each block in a well-formed blk file.
    FlatFilePos pos{0, BLOCK_SERIALIZATION_HEADER_SIZE};
    BOOST_CHECK_EQUAL(blockman.SaveBlockToDisk(params->GenesisBlock(), 0, &pos).nPos, BLOCK_SERIALIZATION_HEADER_SIZE);
    // now simulate what happens after reindex for the first new block processed
    // the actual block contents don't matter, just that it's a block.
    // verify that the write position is at offset 0x12d.
    // this is a check to make sure that https://github.com/bitcoin/bitcoin/issues/21379 does not recur
    // 8 bytes (for serialization header) + 285 (for serialized genesis block) = 293
    // add another 8 bytes for the second block's serialization header and we get 293 + 8 = 301
    FlatFilePos actual{blockman.SaveBlockToDisk(params->GenesisBlock(), 1, nullptr)};
    BOOST_CHECK_EQUAL(actual.nPos, BLOCK_SERIALIZATION_HEADER_SIZE + ::GetSerializeSize(TX_WITH_WITNESS(params->GenesisBlock())) + BLOCK_SERIALIZATION_HEADER_SIZE);
}

BOOST_FIXTURE_TEST_CASE(blockmanager_scan_unlink_already_pruned_files, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    const auto& chainman = Assert(m_node.chainman);
    auto& blockman = chainman->m_blockman;
    const CBlockIndex* old_tip{WITH_LOCK(chainman->GetMutex(), return chainman->ActiveChain().Tip())};
    WITH_LOCK(chainman->GetMutex(), blockman.GetBlockFileInfo(old_tip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    // Prune the older block file, but don't unlink it
    int file_number;
    {
        LOCK(chainman->GetMutex());
        file_number = old_tip->GetBlockPos().nFile;
        blockman.PruneOneBlockFile(file_number);
    }

    const FlatFilePos pos(file_number, 0);

    // Check that the file is not unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // if m_have_pruned is not yet set
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(!blockman.OpenBlockFile(pos, true).IsNull());

    // Check that the file is unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // once m_have_pruned is set
    blockman.m_have_pruned = true;
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(blockman.OpenBlockFile(pos, true).IsNull());

    // Check that calling with already pruned files doesn't cause an error
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());

    // Check that the new tip file has not been removed
    const CBlockIndex* new_tip{WITH_LOCK(chainman->GetMutex(), return chainman->ActiveChain().Tip())};
    BOOST_CHECK_NE(old_tip, new_tip);
    const int new_file_number{WITH_LOCK(chainman->GetMutex(), return new_tip->GetBlockPos().nFile)};
    const FlatFilePos new_pos(new_file_number, 0);
    BOOST_CHECK(!blockman.OpenBlockFile(new_pos, true).IsNull());
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_availability, TestChain100Setup)
{
    // The goal of the function is to return the first not pruned block in the range [upper_block, lower_block].
    LOCK(::cs_main);
    auto& chainman = m_node.chainman;
    auto& blockman = chainman->m_blockman;
    const CBlockIndex& tip = *chainman->ActiveTip();

    // Function to prune all blocks from 'last_pruned_block' down to the genesis block
    const auto& func_prune_blocks = [&](CBlockIndex* last_pruned_block)
    {
        LOCK(::cs_main);
        CBlockIndex* it = last_pruned_block;
        while (it != nullptr && it->nStatus & BLOCK_HAVE_DATA) {
            it->nStatus &= ~BLOCK_HAVE_DATA;
            it = it->pprev;
        }
    };

    // 1) Return genesis block when all blocks are available
    BOOST_CHECK_EQUAL(blockman.GetFirstStoredBlock(tip), chainman->ActiveChain()[0]);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *chainman->ActiveChain()[0]));

    // 2) Check lower_block when all blocks are available
    CBlockIndex* lower_block = chainman->ActiveChain()[tip.nHeight / 2];
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *lower_block));

    // Prune half of the blocks
    int height_to_prune = tip.nHeight / 2;
    CBlockIndex* first_available_block = chainman->ActiveChain()[height_to_prune + 1];
    CBlockIndex* last_pruned_block = first_available_block->pprev;
    func_prune_blocks(last_pruned_block);

    // 3) The last block not pruned is in-between upper-block and the genesis block
    BOOST_CHECK_EQUAL(blockman.GetFirstStoredBlock(tip), first_available_block);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *first_available_block));
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *last_pruned_block));
}

BOOST_AUTO_TEST_CASE(blockmanager_flush_block_file)
{
    KernelNotifications notifications{*Assert(m_node.shutdown), m_node.exit_status};
    node::BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
    };
    BlockManager blockman{*Assert(m_node.shutdown), blockman_opts};

    // Test blocks with no transactions, not even a coinbase
    CBlock block1;
    block1.nVersion = 1;
    CBlock block2;
    block2.nVersion = 2;
    CBlock block3;
    block3.nVersion = 3;

    // They are 80 bytes header + 1 byte 0x00 for vtx length
    constexpr int TEST_BLOCK_SIZE{81};

    // Blockstore is empty
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), 0);

    // Write the first block; dbp=nullptr means this block doesn't already have a disk
    // location, so allocate a free location and write it there.
    FlatFilePos pos1{blockman.SaveBlockToDisk(block1, /*nHeight=*/1, /*dbp=*/nullptr)};

    // Write second block
    FlatFilePos pos2{blockman.SaveBlockToDisk(block2, /*nHeight=*/2, /*dbp=*/nullptr)};

    // Two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (TEST_BLOCK_SIZE + BLOCK_SERIALIZATION_HEADER_SIZE) * 2);

    // First two blocks are written as expected
    // Errors are expected because block data is junk, thrown AFTER successful read
    CBlock read_block;
    BOOST_CHECK_EQUAL(read_block.nVersion, 0);
    {
        ASSERT_DEBUG_LOG("ReadBlockFromDisk: Errors in block header");
        BOOST_CHECK(!blockman.ReadBlockFromDisk(read_block, pos1));
        BOOST_CHECK_EQUAL(read_block.nVersion, 1);
    }
    {
        ASSERT_DEBUG_LOG("ReadBlockFromDisk: Errors in block header");
        BOOST_CHECK(!blockman.ReadBlockFromDisk(read_block, pos2));
        BOOST_CHECK_EQUAL(read_block.nVersion, 2);
    }

    // When FlatFilePos* dbp is given, SaveBlockToDisk() will not write or
    // overwrite anything to the flat file block storage. It will, however,
    // update the blockfile metadata. This is to facilitate reindexing
    // when the user has the blocks on disk but the metadata is being rebuilt.
    // Verify this behavior by attempting (and failing) to write block 3 data
    // to block 2 location.
    CBlockFileInfo* block_data = blockman.GetBlockFileInfo(0);
    BOOST_CHECK_EQUAL(block_data->nBlocks, 2);
    BOOST_CHECK(blockman.SaveBlockToDisk(block3, /*nHeight=*/3, /*dbp=*/&pos2) == pos2);
    // Metadata is updated...
    BOOST_CHECK_EQUAL(block_data->nBlocks, 3);
    // ...but there are still only two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (TEST_BLOCK_SIZE + BLOCK_SERIALIZATION_HEADER_SIZE) * 2);

    // Block 2 was not overwritten:
    //   SaveBlockToDisk() did not call WriteBlockToDisk() because `FlatFilePos* dbp` was non-null
    blockman.ReadBlockFromDisk(read_block, pos2);
    BOOST_CHECK_EQUAL(read_block.nVersion, 2);
}

// An undo entry spending one BLSCT output with a random range proof.
static CTxUndo RandomBlsctTxUndo()
{
    CTxOut out;
    out.scriptPubKey = CScript() << OP_TRUE;
    out.blsctData.spendingKey = BlstG1Point::Rand();
    out.blsctData.ephemeralKey = BlstG1Point::Rand();
    out.blsctData.blindingKey = BlstG1Point::Rand();
    auto& proof = out.blsctData.rangeProof;
    proof.Vs.Add(BlstG1Point::Rand());
    proof.Ls.Add(BlstG1Point::Rand());
    proof.Rs.Add(BlstG1Point::Rand());
    proof.A = BlstG1Point::Rand();
    proof.A_wip = BlstG1Point::Rand();
    proof.B = BlstG1Point::Rand();
    proof.r_prime = BlstScalar::Rand();
    proof.tau_x = BlstScalar::Rand();
    CTxUndo txundo;
    txundo.vprevout.emplace_back(out, /*nHeightIn=*/1, /*fCoinBaseIn=*/false);
    return txundo;
}

BOOST_FIXTURE_TEST_CASE(blockmanager_undo_round_trip_parallel_blsct, TestChain100Setup)
{
    // UndoWriteToDisk runs min(cap, n / UNDO_WRITE_MIN_ENTRIES_PER_THREAD)
    // threads (at least 1; cap 0 is one per core) over ceil-sized chunks.
    // Block sizes off a multiple of the thread count leave a short last
    // chunk, which is where a chunking slip drops or repeats entries.
    constexpr size_t M{UNDO_WRITE_MIN_ENTRIES_PER_THREAD};
    const std::vector<size_t> block_sizes{
        2 * M - 1, // one thread under every cap: the min-entries rule
        3 * M + 1, // 3 threads at cap 64 (min-entries rule), 2 at cap 2 (-par)
        8 * M + 7, // 8 threads at cap 64 (min-entries rule), 2 or 3 at caps 2 and 3 (-par)
    };

    CBlockUndo all_undo;
    all_undo.vtxundo.reserve(block_sizes.back());
    for (size_t i = 0; i < block_sizes.back(); ++i) {
        all_undo.vtxundo.push_back(RandomBlsctTxUndo());
    }

    auto& blockman{m_node.chainman->m_blockman};
    LOCK(cs_main);
    CBlockIndex& tip{*Assert(m_node.chainman->ActiveChain().Tip())};
    for (size_t n : block_sizes) {
        CBlockUndo blockundo;
        blockundo.vtxundo.assign(all_undo.vtxundo.begin(), all_undo.vtxundo.begin() + n);
        for (size_t cap : {size_t{0}, size_t{1}, size_t{2}, size_t{3}, size_t{64}}) {
            // Drop the tip's undo position so WriteUndoDataForBlock writes ours.
            tip.nStatus &= ~BLOCK_HAVE_UNDO;
            BlockValidationState state;
            BOOST_REQUIRE(blockman.WriteUndoDataForBlock(blockundo, state, tip, cap));

            CBlockUndo read_undo;
            if (!blockman.UndoReadFromDisk(read_undo, tip)) {
                BOOST_ERROR("undo of " << n << " entries with cap " << cap << " does not read back");
                continue;
            }
            if (read_undo.vtxundo.size() != n) {
                BOOST_ERROR("undo of " << n << " entries with cap " << cap << " read back " << read_undo.vtxundo.size());
                continue;
            }
            for (size_t i = 0; i < n; ++i) {
                const CTxOut& written{blockundo.vtxundo[i].vprevout.at(0).out};
                const CTxOut& read{read_undo.vtxundo[i].vprevout.at(0).out};
                // Undo data keeps the commitment, not the rest of the range proof.
                BOOST_CHECK_MESSAGE(read.blsctData.rangeProof.Vs[0] == written.blsctData.rangeProof.Vs[0],
                                    "entry " << i << " of " << n << " commitment differs with cap " << cap);
                BOOST_CHECK_MESSAGE(read.blsctData.spendingKey == written.blsctData.spendingKey,
                                    "entry " << i << " of " << n << " spending key differs with cap " << cap);
                BOOST_CHECK_EQUAL(read.blsctData.rangeProof.Ls.Size(), 0U);
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(blockmanager_undo_write_spawns_at_most_thread_cap, TestChain100Setup,
                        *boost::unit_test::precondition(CanCountThreads))
{
    // The undo write takes its workers out of the caller's -par budget: with
    // a cap of N it runs the calling thread plus at most N - 1 workers.
    // Enough entries (copies of one, as the content does not matter here)
    // that the workers live long enough for the sampler to see them.
    constexpr size_t NUM_TX_UNDO{20000};
    constexpr size_t MAX_CAP{3};
    // The cap, not the min-entries rule, has to be what limits the pool here.
    static_assert(NUM_TX_UNDO / UNDO_WRITE_MIN_ENTRIES_PER_THREAD > MAX_CAP);
    CBlockUndo blockundo;
    blockundo.vtxundo.assign(NUM_TX_UNDO, RandomBlsctTxUndo());

    auto& blockman{m_node.chainman->m_blockman};
    LOCK(cs_main);
    CBlockIndex& tip{*Assert(m_node.chainman->ActiveChain().Tip())};
    for (size_t cap{1}; cap <= MAX_CAP; ++cap) {
        // Every measurement must stay within the cap; a cap above 1 is
        // remeasured until the sampler has seen the pool spawn a worker.
        bool seen{false};
        for (int attempt = 0; attempt < MAX_POOL_ATTEMPTS; ++attempt) {
            tip.nStatus &= ~BLOCK_HAVE_UNDO;
            const size_t extra{PeakExtraThreads([&] {
                BlockValidationState state;
                BOOST_CHECK(blockman.WriteUndoDataForBlock(blockundo, state, tip, cap));
            })};
            BOOST_CHECK_MESSAGE(extra <= cap - 1, "undo write with cap " << cap << " ran " << extra << " extra threads");
            seen |= extra > 0;
            if (cap == 1 || seen) break;
        }
        if (cap > 1) {
            BOOST_CHECK_MESSAGE(seen, "undo write with cap " << cap << " ran no extra threads in " << MAX_POOL_ATTEMPTS << " attempts");
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
