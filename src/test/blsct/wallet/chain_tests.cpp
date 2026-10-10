// Copyright (c) 2023-2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <dbwrapper.h>
#include <kernel/chain.h>
#include <node/miner.h>
#include <policy/fees.h>
#include <pow.h>
#include <util/vector.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <algorithm>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(chain_tests, WalletTestingSetup)

BOOST_FIXTURE_TEST_CASE(SyncTest, TestBLSCTChain100Setup)
{
    CreateAndProcessBlock({});
    auto wallet = CreateBLSCTWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()));
    BOOST_CHECK(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    auto blsct_km = wallet->GetBLSCTKeyMan();
    auto walletDestination = blsct::SubAddress(std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value()));

    LOCK(wallet->cs_wallet);

    for (size_t i = 0; i <= COINBASE_MATURITY; i++) {
        CreateAndProcessBlock({}, walletDestination);
    }

    BOOST_CHECK(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    BOOST_CHECK(GetBalance(*wallet).m_mine_trusted == 4 * COIN);
    BOOST_CHECK(GetBalance(*wallet).m_mine_immature == 4 * COINBASE_MATURITY * COIN);

    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();

    BOOST_CHECK(coins.size() == 1);

    // Create Transaction sending to another address
    // Send to a wallet-owned destination: a default-constructed (zero-key)
    // SubAddress is anyone-can-spend and is rejected by CreateOutput.
    auto tx = blsct::TxFactory::CreateTransaction(wallet.get(), wallet->GetOrCreateBLSCTKeyMan(), blsct::CreateTransactionData{walletDestination, 1 * COIN, "test"});

    BOOST_CHECK(tx != std::nullopt);

    auto block = CreateAndProcessBlock({tx->tx}, walletDestination);

    BOOST_CHECK(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    auto wtx = wallet->GetWalletTx(block.vtx[1]->GetHash());

    BOOST_CHECK(wtx != nullptr);

    auto wtx_out = wallet->GetWalletTxFromOutpoint(COutPoint(block.vtx[1]->vout[0].GetHash()));

    BOOST_CHECK(wtx_out != nullptr);
    BOOST_CHECK(wtx_out == wtx);
}

// End-to-end reorg regression for the DisconnectBlock vout-order fix: a single
// aggregated transaction carries a CREATE_TOKEN output followed by a MINT
// output for the same token. Connect applies the predicates in forward vout
// order (create, then mint). Disconnect must unwind them in reverse vout
// order: unwinding the create first erases the token entry, the mint revert
// then fails its token lookup, DisconnectBlock returns DISCONNECT_FAILED and
// the node wedges unable to reorg. With the fix, invalidateblock + reconnect
// round-trips cleanly.
BOOST_FIXTURE_TEST_CASE(TokenCreateMintReorgTest, TestBLSCTChain100Setup)
{
    CreateAndProcessBlock({});
    auto wallet = CreateBLSCTWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()));
    BOOST_CHECK(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    auto blsct_km = wallet->GetBLSCTKeyMan();
    auto walletDestination = blsct::SubAddress(std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value()));

    LOCK(wallet->cs_wallet);

    // Two mature coinbases: the create tx and the mint tx each need their own
    // fee input (the second tx cannot see the first one's spend, so its coin
    // is locked below to keep the aggregated inputs disjoint).
    for (size_t i = 0; i <= COINBASE_MATURITY + 1; i++) {
        CreateAndProcessBlock({}, walletDestination);
    }
    BOOST_CHECK(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    blsct::TokenInfo tokenInfo;
    tokenInfo.type = blsct::TOKEN;
    tokenInfo.nTotalSupply = 1000 * COIN;
    tokenInfo.mapMetadata["name"] = "ReorgTest";
    tokenInfo.publicKey = blsct_km->GetTokenKey((HashWriter{} << tokenInfo.mapMetadata << tokenInfo.nTotalSupply).GetHash()).GetPublicKey();
    const uint256 tokenId = tokenInfo.publicKey.GetHash();
    const CAmount mintAmount = 100 * COIN;

    auto create_tx = blsct::TxFactory::CreateTransaction(wallet.get(), blsct_km, blsct::CreateTransactionData{tokenInfo});
    BOOST_REQUIRE(create_tx != std::nullopt);

    for (const auto& in : create_tx->tx.vin) {
        BOOST_REQUIRE(wallet->LockCoin(in.prevout));
    }

    auto mint_tx = blsct::TxFactory::CreateTransaction(wallet.get(), blsct_km, blsct::CreateTransactionData{tokenInfo, mintAmount, walletDestination});
    BOOST_REQUIRE(mint_tx != std::nullopt);

    auto aggregated = blsct::AggregateTransactions({MakeTransactionRef(create_tx->tx), MakeTransactionRef(mint_tx->tx)});

    // The shape under test: the create predicate must sit at a lower vout
    // index than the mint predicate of the same transaction.
    int create_idx = -1, mint_idx = -1;
    for (size_t o = 0; o < aggregated->vout.size(); o++) {
        if (aggregated->vout[o].predicate.size() == 0) continue;
        auto parsed = blsct::ParsePredicate(aggregated->vout[o].predicate);
        if (parsed.IsCreateTokenPredicate()) create_idx = o;
        if (parsed.IsMintTokenPredicate()) mint_idx = o;
    }
    BOOST_REQUIRE(create_idx >= 0 && mint_idx >= 0 && create_idx < mint_idx);

    const CBlock block = CreateAndProcessBlock({CMutableTransaction(*aggregated)}, walletDestination);
    BOOST_REQUIRE_EQUAL(WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockHash()), block.GetHash());

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        blsct::TokenEntry entry;
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().CoinsTip().GetToken(tokenId, entry));
        BOOST_CHECK_EQUAL(entry.nSupply, mintAmount);
    }

    CBlockIndex* pindex = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash()));
    BOOST_REQUIRE(pindex != nullptr);

    // Disconnect: without the reverse-order unwind this fails with
    // DISCONNECT_FAILED.
    BlockValidationState state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, pindex));
    BOOST_REQUIRE(state.IsValid());

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        BOOST_REQUIRE(m_node.chainman->ActiveChain().Tip()->GetBlockHash() != block.GetHash());
        blsct::TokenEntry entry;
        BOOST_CHECK(!m_node.chainman->ActiveChainstate().CoinsTip().GetToken(tokenId, entry));
    }

    // Reconnect: the block reconnects cleanly and the token state returns.
    WITH_LOCK(Assert(m_node.chainman)->GetMutex(), m_node.chainman->ActiveChainstate().ResetBlockFailureFlags(pindex));
    BlockValidationState state2;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().ActivateBestChain(state2));

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        BOOST_REQUIRE_EQUAL(m_node.chainman->ActiveChain().Tip()->GetBlockHash(), block.GetHash());
        blsct::TokenEntry entry;
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().CoinsTip().GetToken(tokenId, entry));
        BOOST_CHECK_EQUAL(entry.nSupply, mintAmount);
    }
}

// Cross-transaction predicate ordering on disconnect. ConnectBlock runs a
// BLSCT block's coinbase (vtx[0]) through its token predicates AFTER the loop
// over the other transactions, so a coinbase MINT of a token CREATEd by an
// ordinary transaction in the same block connects: create first, coinbase mint
// last. DisconnectBlock must therefore revert the coinbase's predicates FIRST,
// before the reverse transaction loop reaches the create. Reverting them in
// the loop's last-to-first order would erase the token before the coinbase
// mint revert looks it up, and the disconnect would fail (DISCONNECT_FAILED),
// leaving the block impossible to reorg past, invalidate or verify at level 3.
// The stock miner never puts a token predicate in the coinbase, so the block
// is hand-built here.
BOOST_FIXTURE_TEST_CASE(DisconnectRevertsCoinbasePredicatesFirst, TestBLSCTChain100Setup)
{
    CreateAndProcessBlock({});
    auto wallet = CreateBLSCTWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()));
    BOOST_CHECK(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    auto blsct_km = wallet->GetBLSCTKeyMan();
    auto walletDestination = blsct::SubAddress(std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value()));

    LOCK(wallet->cs_wallet);

    // One mature coinbase funds the create tx's fee; +1 for headroom.
    for (size_t i = 0; i <= COINBASE_MATURITY + 1; i++) {
        CreateAndProcessBlock({}, walletDestination);
    }
    BOOST_CHECK(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    // Token T: created by an ordinary (non-coinbase) transaction, minted by the
    // coinbase of the same block. The coinbase mint must be signed by T's token
    // key, so derive the exact scalar the wallet factory uses for the create
    // (txfactory.cpp: GetTokenKey(hash(metadata, totalSupply)).GetScalar()).
    blsct::TokenInfo token;
    token.type = blsct::TOKEN;
    token.nTotalSupply = 1000 * COIN;
    token.mapMetadata["name"] = "DisconnectOrder";
    const uint256 tokenKeyHash = (HashWriter{} << token.mapMetadata << token.nTotalSupply).GetHash();
    const Scalar tokenKey = blsct_km->GetTokenKey(tokenKeyHash).GetScalar();
    token.publicKey = blsct_km->GetTokenKey(tokenKeyHash).GetPublicKey();
    const uint256 tokenId = token.publicKey.GetHash();
    const CAmount mintAmount = 100 * COIN;

    auto create_tx = blsct::TxFactory::CreateTransaction(wallet.get(), blsct_km, blsct::CreateTransactionData{token});
    BOOST_REQUIRE(create_tx != std::nullopt);

    WITH_LOCK(::cs_main, m_node.chainman->ActiveChainstate().ForceFlushStateToDisk());

    CBlock block = CreateBlock({create_tx->tx}, m_node.chainman->ActiveChainstate(), walletDestination);

    // Splice a MINT of T into the coinbase. The mint output carries a range
    // proof and destination keys, so aggregate its own output+balance signature
    // (UnsignedOutput::GetSignature) plus the token key's mint authorization
    // into the coinbase's existing aggregate signature. transcript_v2 is true on
    // blsctregtest (nBLSCTProofV2Height = 0), matching what the verifier applies.
    CMutableTransaction coinbase{*block.vtx[0]};
    const blsct::UnsignedOutput mintOut = blsct::CreateOutput(walletDestination.GetKeys(), mintAmount, Scalar::Rand(), tokenKey, token.publicKey, /*transcript_v2=*/true);
    BOOST_REQUIRE(mintOut.out.HasBLSCTRangeProof() && mintOut.out.HasBLSCTKeys());
    coinbase.vout.push_back(mintOut.out);
    coinbase.txSig = blsct::Signature::Aggregate({coinbase.txSig, mintOut.GetSignature(), blsct::PrivateKey(tokenKey).Sign(mintOut.out.GetHash())});
    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    node::RegenerateCommitments(block, *m_node.chainman);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, m_node.chainman->GetConsensus())) ++block.nNonce;

    // Connect: the block is accepted and the coinbase mint applies on top of the
    // ordinary transaction's create (supply == mintAmount).
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), true, true, nullptr));

    CBlockIndex* pindex{nullptr};
    {
        LOCK(::cs_main);
        Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
        BOOST_REQUIRE_EQUAL(chainstate.m_chain.Tip()->GetBlockHash(), block.GetHash());
        blsct::TokenEntry entry;
        BOOST_REQUIRE_MESSAGE(chainstate.CoinsTip().GetToken(tokenId, entry), "connect did not create/mint the token");
        BOOST_CHECK_EQUAL(entry.nSupply, mintAmount);
        pindex = chainstate.m_blockman.LookupBlockIndex(block.GetHash());
        BOOST_REQUIRE(pindex != nullptr);

        // verifychain at level 3 disconnects the tip in memory, so it fails
        // unless the coinbase mint is reverted before the create.
        const VerifyDBResult verify = CVerifyDB(m_node.chainman->GetNotifications()).VerifyDB(
            chainstate, m_node.chainman->GetConsensus(), chainstate.CoinsTip(), /*nCheckLevel=*/3, /*nCheckDepth=*/1);
        BOOST_CHECK_MESSAGE(verify == VerifyDBResult::SUCCESS,
                            "VerifyDB level 3 failed to disconnect the coinbase-mint block");
    }

    // Disconnect: the block rolls back, the tip returns to its parent and the
    // token the block created is gone again.
    BlockValidationState state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, pindex));
    BOOST_REQUIRE(state.IsValid());
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_EQUAL(m_node.chainman->ActiveChain().Tip()->GetBlockHash(), pindex->pprev->GetBlockHash());
        blsct::TokenEntry entry;
        BOOST_CHECK(!m_node.chainman->ActiveChainstate().CoinsTip().GetToken(tokenId, entry));
    }

    // Reconnect: the block applies again and the token state returns.
    WITH_LOCK(::cs_main, m_node.chainman->ActiveChainstate().ResetBlockFailureFlags(pindex));
    BlockValidationState state2;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().ActivateBestChain(state2));
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_EQUAL(m_node.chainman->ActiveChain().Tip()->GetBlockHash(), block.GetHash());
        blsct::TokenEntry entry;
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().CoinsTip().GetToken(tokenId, entry));
        BOOST_CHECK_EQUAL(entry.nSupply, mintAmount);
    }
}

// Regression: a consolidating stakelock spends the wallet's previous staked
// commitment output. CachedTxIsTrusted used to reject that input because its
// isminetype is ISMINE_STAKED_COMMITMENT_BLSCT (neither "spendable" value),
// classifying the whole transaction as untrusted -- so while the stake tx sat
// in the mempool the wallet reported the entire in-flight amount under the
// untrusted pending balance and pending_staked_commitment_balance stayed 0.
BOOST_FIXTURE_TEST_CASE(StakelockConsolidationPendingBalanceTest, TestBLSCTChain100Setup)
{
    CreateAndProcessBlock({});
    auto wallet = CreateBLSCTWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()));
    BOOST_CHECK(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    auto blsct_km = wallet->GetBLSCTKeyMan();
    auto walletDestination = blsct::SubAddress(std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value()));

    LOCK(wallet->cs_wallet);

    // Enough mature 4-COIN coinbases to cover the 100-COIN blsctregtest
    // minimum stake plus fees for two stake transactions.
    const CAmount min_stake = Params().GetConsensus().nPePoSMinStakeAmount;
    const int extra_blocks = static_cast<int>(min_stake / (4 * COIN)) + 5;
    for (int i = 0; i <= COINBASE_MATURITY + extra_blocks; i++) {
        CreateAndProcessBlock({}, walletDestination);
    }
    BOOST_CHECK(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    auto stakeDest = blsct::SubAddress(std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(blsct::STAKING_ACCOUNT).value()));

    // First stakelock: lock the minimum stake and confirm it.
    blsct::CreateTransactionData stake1(stakeDest, min_stake, "", TokenId(), blsct::CreateTransactionType::STAKED_COMMITMENT, min_stake);
    auto tx1 = blsct::TxFactory::CreateTransaction(wallet.get(), blsct_km, stake1);
    BOOST_REQUIRE(tx1 != std::nullopt);
    CreateAndProcessBlock({tx1->tx}, walletDestination);
    BOOST_CHECK(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    const Balance before = GetBalance(*wallet);
    BOOST_REQUIRE_EQUAL(before.m_mine_staked_commitment, min_stake);
    BOOST_CHECK_EQUAL(before.m_mine_pending_staked_commitment, 0);

    // Second stakelock with consolidation (the default): folds the confirmed
    // commitment plus a fresh 4 COIN into one new commitment output.
    const CAmount added = 4 * COIN;
    blsct::CreateTransactionData stake2(stakeDest, added, "", TokenId(), blsct::CreateTransactionType::STAKED_COMMITMENT, min_stake);
    BOOST_REQUIRE(stake2.fConsolidateStakedCommitments);
    auto tx2 = blsct::TxFactory::CreateTransaction(wallet.get(), blsct_km, stake2);
    BOOST_REQUIRE(tx2 != std::nullopt);

    const auto tx2ref = MakeTransactionRef(tx2->tx);
    const auto res = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ProcessTransaction(tx2ref));
    BOOST_REQUIRE_MESSAGE(res.m_result_type == MempoolAcceptResult::ResultType::VALID,
                          "mempool rejected consolidating stakelock: " + res.m_state.ToString());
    wallet->transactionAddedToMempool(tx2ref);

    // The in-flight consolidated stake must be reported as trusted pending
    // staked commitment, not as untrusted pending balance.
    const Balance after = GetBalance(*wallet);
    BOOST_CHECK_EQUAL(after.m_mine_staked_commitment, 0);
    BOOST_CHECK_EQUAL(after.m_mine_pending_staked_commitment, before.m_mine_staked_commitment + added);
    BOOST_CHECK_EQUAL(after.m_mine_untrusted_pending, 0);
}

// A scan without fUpdate that meets a transaction whose outputs the wallet
// already holds must still record that transaction's spends. Knowing the
// outputs does not mean the inputs are marked spent: a block disconnect
// un-spends them and leaves the outputs in place. AddToWalletIfInvolvingMe's
// output-storage path used to return before its vin loop in that case, so
// such a scan could never repair the spend. The disconnect also demotes the
// block's own outputs to inactive (the coinbase's to abandoned), and the scan
// must bring those back to confirmed too.
BOOST_FIXTURE_TEST_CASE(OutputStorageScanRecordsKnownTxSpendTest, TestBLSCTChain100Setup)
{
    CreateAndProcessBlock({});
    CChain& cchain = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain());

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK2(wallet->cs_wallet, ::cs_main);
        wallet->SetLastBlockProcessed(cchain.Height(), cchain.Tip()->GetBlockHash());
    }
    wallet->LoadWallet();
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    blsct_km->SetHDSeed(BlstScalar(uint256(uint64_t{1})));
    BOOST_REQUIRE(blsct_km->NewSubAddressPool());
    BOOST_REQUIRE(blsct_km->NewSubAddressPool(-1));
    auto walletDestination = blsct::SubAddress(std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value()));

    for (size_t i = 0; i <= COINBASE_MATURITY; i++) {
        CreateAndProcessBlock({}, walletDestination);
    }
    BOOST_REQUIRE(SyncBLSCTWallet(wallet, cchain));

    auto tx = blsct::TxFactory::CreateTransaction(wallet.get(), blsct_km, blsct::CreateTransactionData{walletDestination, 1 * COIN, "test"});
    BOOST_REQUIRE(tx != std::nullopt);
    BOOST_REQUIRE(!tx->tx.vin.empty());
    const COutPoint spent{tx->tx.vin[0].prevout};
    BOOST_REQUIRE(wallet->GetWalletOutput(spent) != nullptr);

    const CBlock block = CreateAndProcessBlock({tx->tx}, walletDestination);
    BOOST_REQUIRE(SyncBLSCTWallet(wallet, cchain));
    BOOST_REQUIRE(wallet->GetWalletOutput(spent)->IsSpent());

    // The wallet's own outputs of the block: the send's change and the coinbase.
    std::vector<COutPoint> own_outputs;
    for (const auto& block_tx : block.vtx) {
        for (const CTxOut& out : block_tx->vout) {
            if (wallet->GetWalletOutput(COutPoint{out.GetHash()})) own_outputs.emplace_back(out.GetHash());
        }
    }
    BOOST_REQUIRE(!own_outputs.empty());
    BOOST_REQUIRE(wallet->GetWalletOutput(COutPoint{block.vtx[0]->vout[0].GetHash()}) != nullptr);
    BOOST_REQUIRE(std::any_of(block.vtx[1]->vout.begin(), block.vtx[1]->vout.end(), [&](const CTxOut& out) {
        return wallet->GetWalletOutput(COutPoint{out.GetHash()}) != nullptr;
    }));

    // The wallet sees the block disconnected: the spend is undone, while the
    // spending transaction's outputs stay in mapOutputs.
    const CBlockIndex* pindex = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash()));
    BOOST_REQUIRE(pindex != nullptr);
    wallet->blockDisconnected(kernel::MakeBlockInfo(pindex, &block));
    BOOST_REQUIRE(!wallet->GetWalletOutput(spent)->IsSpent());
    for (const COutPoint& outpoint : own_outputs) {
        BOOST_REQUIRE(wallet->GetWalletOutput(outpoint)->state<TxStateInactive>());
    }

    // The block is still on the active chain, so a scan without fUpdate meets
    // the spending transaction again and must record its spend.
    BOOST_REQUIRE(SyncBLSCTWallet(wallet, cchain));
    BOOST_CHECK_MESSAGE(wallet->GetWalletOutput(spent)->IsSpent(),
                        "a scan without fUpdate did not record the spend of a known transaction");
    for (const COutPoint& outpoint : own_outputs) {
        const auto* confirmed = wallet->GetWalletOutput(outpoint)->state<TxStateConfirmed>();
        BOOST_CHECK_MESSAGE(confirmed && confirmed->confirmed_block_hash == block.GetHash(),
                            "a scan without fUpdate left an output of an active block unconfirmed: " + outpoint.ToString());
    }
}

//! Coins database on disk, so a test can reopen it the way a restart would.
struct OnDiskCoinsBLSCTChainSetup : public TestBLSCTChain100Setup {
    OnDiskCoinsBLSCTChainSetup() : TestBLSCTChain100Setup{blsct::SubAddress(), ChainType::BLSCTREGTEST, {}, /*coins_db_in_memory=*/false} {}
};

/**
 * Leave the coins database as a crash part way through flushing the active
 * tip would: marked as between the database's best block and the tip, with
 * only `erased_coins` of the flush written, then replay it as startup does.
 * The tip cache is dropped unflushed.
 */
static void CrashFlushAndReplay(Chainstate& chainstate, const std::vector<COutPoint>& erased_coins) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    // Key prefixes of CCoinsViewDB (txdb.cpp): DB_COIN, DB_BEST_BLOCK, DB_HEAD_BLOCKS.
    constexpr uint8_t db_coin{'C'}, db_best_block{'B'}, db_head_blocks{'H'};

    const uint256 old_tip{chainstate.CoinsDB().GetBestBlock()};
    const uint256 new_tip{chainstate.m_chain.Tip()->GetBlockHash()};
    BOOST_REQUIRE(old_tip != new_tip);
    const fs::path path{*Assert(chainstate.CoinsDB().StoragePath())};
    const size_t db_cache{chainstate.m_coinsdb_cache_size_bytes};
    const size_t tip_cache{chainstate.m_coinstip_cache_size_bytes};

    chainstate.ResetCoinsViews();
    {
        CDBWrapper db{DBParams{.path = path, .cache_bytes = 1 << 20, .obfuscate = true}};
        CDBBatch batch{db};
        batch.Erase(db_best_block);
        batch.Write(db_head_blocks, Vector(new_tip, old_tip));
        for (const COutPoint& outpoint : erased_coins) {
            // A key that matched nothing would leave the coin for SpendCoin
            // to find, and the test would pass without the case it targets.
            BOOST_REQUIRE(db.Exists(std::make_pair(db_coin, outpoint.hash)));
            batch.Erase(std::make_pair(db_coin, outpoint.hash));
        }
        BOOST_REQUIRE(db.WriteBatch(batch, /*fSync=*/true));
    }
    chainstate.InitCoinsDB(db_cache, /*in_memory=*/false, /*should_wipe=*/false);
    BOOST_REQUIRE_EQUAL(chainstate.CoinsDB().GetHeadBlocks().size(), 2U);
    BOOST_REQUIRE(chainstate.ReplayBlocks());
    chainstate.InitCoinsCache(tip_cache);
    BOOST_REQUIRE_EQUAL(chainstate.CoinsTip().GetBestBlock(), new_tip);
    BOOST_REQUIRE(chainstate.CoinsDB().GetHeadBlocks().empty());
}

// ReplayBlocks must apply the token predicates of the blocks it rolls
// forward, both those of ordinary transactions and those of the coinbase,
// which ConnectBlock executes after the other transactions.
BOOST_FIXTURE_TEST_CASE(ReplayAppliesTokenPredicatesTest, OnDiskCoinsBLSCTChainSetup)
{
    CreateAndProcessBlock({});
    auto wallet = CreateBLSCTWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()));
    auto blsct_km = wallet->GetBLSCTKeyMan();
    auto walletDestination = blsct::SubAddress(std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value()));

    LOCK(wallet->cs_wallet);
    for (size_t i = 0; i <= COINBASE_MATURITY; i++) {
        CreateAndProcessBlock({}, walletDestination);
    }
    BOOST_REQUIRE(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    blsct::TokenInfo txToken;
    txToken.type = blsct::TOKEN;
    txToken.nTotalSupply = 1000 * COIN;
    txToken.mapMetadata["name"] = "ReplayTx";
    txToken.publicKey = blsct_km->GetTokenKey((HashWriter{} << txToken.mapMetadata << txToken.nTotalSupply).GetHash()).GetPublicKey();
    auto create_tx = blsct::TxFactory::CreateTransaction(wallet.get(), blsct_km, blsct::CreateTransactionData{txToken});
    BOOST_REQUIRE(create_tx != std::nullopt);

    // A coinbase may carry a create-token output too: the miner signs it
    // with the token key into the coinbase's aggregate signature.
    const Scalar coinbaseTokenKey{Scalar::Rand()};
    blsct::TokenInfo coinbaseToken;
    coinbaseToken.type = blsct::TOKEN;
    coinbaseToken.nTotalSupply = 500 * COIN;
    coinbaseToken.mapMetadata["name"] = "ReplayCoinbase";
    coinbaseToken.publicKey = blsct::PrivateKey(coinbaseTokenKey).GetPublicKey();

    WITH_LOCK(::cs_main, m_node.chainman->ActiveChainstate().ForceFlushStateToDisk());

    CBlock block = CreateBlock({create_tx->tx}, m_node.chainman->ActiveChainstate(), walletDestination);
    CMutableTransaction coinbase{*block.vtx[0]};
    const blsct::UnsignedOutput tokenOut = blsct::CreateOutput(coinbaseTokenKey, coinbaseToken);
    BOOST_REQUIRE(!tokenOut.out.HasBLSCTRangeProof() && !tokenOut.out.HasBLSCTKeys());
    coinbase.vout.push_back(tokenOut.out);
    coinbase.txSig = blsct::Signature::Aggregate({coinbase.txSig, blsct::PrivateKey(coinbaseTokenKey).Sign(tokenOut.out.GetHash())});
    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    node::RegenerateCommitments(block, *m_node.chainman);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, m_node.chainman->GetConsensus())) ++block.nNonce;
    BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(std::make_shared<const CBlock>(block), true, true, nullptr));
    CreateAndProcessBlock({}, walletDestination);

    LOCK(::cs_main);
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    BOOST_REQUIRE_EQUAL(chainstate.m_chain.Tip()->pprev->GetBlockHash(), block.GetHash());
    for (const auto& token : {txToken, coinbaseToken}) {
        blsct::TokenEntry entry;
        BOOST_REQUIRE_MESSAGE(chainstate.CoinsTip().GetToken(token.publicKey.GetHash(), entry), "connect did not create " + token.mapMetadata.at("name"));
    }

    // Replay must roll forward the token block, not only the one after it.
    BOOST_REQUIRE_EQUAL(chainstate.CoinsDB().GetBestBlock(), block.hashPrevBlock);
    CrashFlushAndReplay(chainstate, /*erased_coins=*/{});

    for (const auto& token : {txToken, coinbaseToken}) {
        blsct::TokenEntry entry;
        BOOST_CHECK_MESSAGE(chainstate.CoinsTip().GetToken(token.publicKey.GetHash(), entry), "replay lost " + token.mapMetadata.at("name"));
        BOOST_CHECK_EQUAL(entry.info.nTotalSupply, token.nTotalSupply);
    }
}

// A crash can land after a partial batch has already erased a spent staked
// commitment's coin, while the staked-commitment set itself is only written
// in the final batch. Replaying the spend must still drop the commitment
// from the set, though the coin is no longer there to look up.
BOOST_FIXTURE_TEST_CASE(ReplayRemovesSpentStakedCommitmentTest, OnDiskCoinsBLSCTChainSetup)
{
    CreateAndProcessBlock({});
    auto wallet = CreateBLSCTWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()));
    auto blsct_km = wallet->GetBLSCTKeyMan();
    auto walletDestination = blsct::SubAddress(std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value()));

    LOCK(wallet->cs_wallet);
    const CAmount min_stake = Params().GetConsensus().nPePoSMinStakeAmount;
    const int extra_blocks = static_cast<int>(min_stake / (4 * COIN)) + 5;
    for (int i = 0; i <= COINBASE_MATURITY + extra_blocks; i++) {
        CreateAndProcessBlock({}, walletDestination);
    }
    BOOST_REQUIRE(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    auto stakeDest = blsct::SubAddress(std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(blsct::STAKING_ACCOUNT).value()));
    auto stake1 = blsct::TxFactory::CreateTransaction(wallet.get(), blsct_km, blsct::CreateTransactionData(stakeDest, min_stake, "", TokenId(), blsct::CreateTransactionType::STAKED_COMMITMENT, min_stake));
    BOOST_REQUIRE(stake1 != std::nullopt);
    CreateAndProcessBlock({stake1->tx}, walletDestination);
    BOOST_REQUIRE(SyncBLSCTWallet(wallet, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain())));

    const CTransaction stake1_tx{stake1->tx};
    std::optional<COutPoint> staked_outpoint;
    BlstG1Point staked_point;
    for (size_t o = 0; o < stake1_tx.vout.size(); o++) {
        if (!stake1_tx.vout[o].IsStakedCommitment()) continue;
        staked_outpoint = COutPoint{stake1_tx.GetOutputId(o)};
        staked_point = stake1_tx.vout[o].blsctData.rangeProof.Vs[0];
    }
    BOOST_REQUIRE(staked_outpoint.has_value());

    {
        LOCK(::cs_main);
        m_node.chainman->ActiveChainstate().ForceFlushStateToDisk();
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().CoinsDB().GetStakedCommitments().Exists(staked_point));
    }

    // Consolidating spends the first commitment into a new one.
    blsct::CreateTransactionData stake2_data(stakeDest, 4 * COIN, "", TokenId(), blsct::CreateTransactionType::STAKED_COMMITMENT, min_stake);
    BOOST_REQUIRE(stake2_data.fConsolidateStakedCommitments);
    auto stake2 = blsct::TxFactory::CreateTransaction(wallet.get(), blsct_km, stake2_data);
    BOOST_REQUIRE(stake2 != std::nullopt);
    BOOST_REQUIRE(std::any_of(stake2->tx.vin.begin(), stake2->tx.vin.end(), [&](const CTxIn& in) { return in.prevout == *staked_outpoint; }));
    CreateAndProcessBlock({stake2->tx}, walletDestination);

    LOCK(::cs_main);
    Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
    const auto expected = chainstate.CoinsTip().GetStakedCommitments();
    BOOST_REQUIRE(!expected.Exists(staked_point));

    CrashFlushAndReplay(chainstate, /*erased_coins=*/{*staked_outpoint});

    const auto replayed = chainstate.CoinsTip().GetStakedCommitments();
    BOOST_CHECK_MESSAGE(!replayed.Exists(staked_point), "replay kept the spent staked commitment");
    BOOST_CHECK_EQUAL(replayed.Size(), expected.Size());
    const auto expected_points = expected.GetElements();
    for (size_t i = 0; i < expected_points.Size(); i++) BOOST_CHECK(replayed.Exists(expected_points[i]));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
