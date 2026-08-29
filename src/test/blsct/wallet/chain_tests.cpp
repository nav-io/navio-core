// Copyright (c) 2023-2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <policy/fees.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

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

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
