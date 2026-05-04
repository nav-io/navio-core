// Copyright (c) 2023-2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/pos/pos.h>
#include <blsct/pos/proof_logic.h>
#include <blsct/wallet/txfactory.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <core_io.h>
#include <policy/fees.h>
#include <test/util/random.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(pos_chain_tests, WalletTestingSetup)

Coin CreateCoin(const blsct::DoublePublicKey& recvAddress)
{
    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test", TokenId(), Scalar::Rand(), blsct::CreateTransactionType::STAKED_COMMITMENT, 1000 * COIN);
    coin.nHeight = 1;
    coin.out = out.out;
    return coin;
}

BOOST_FIXTURE_TEST_CASE(StakedCommitment, TestBLSCTChain100Setup)
{
    auto setup = SetMemProofSetup<Arith>::Get();

    range_proof::GeneratorsFactory<Mcl> gf;
    range_proof::Generators<Arith> gen = gf.GetInstance(TokenId());

    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(wallet.cs_wallet);
    auto blsct_km = wallet.GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    COutPoint outpoint{Txid::FromUint256(InsecureRand256())};
    COutPoint outpoint2{Txid::FromUint256(InsecureRand256())};
    COutPoint outpoint3{Txid::FromUint256(InsecureRand256())};

    Coin coin = CreateCoin(recvAddress);
    Coin coin2 = CreateCoin(recvAddress);
    Coin coin3;

    auto out3 = blsct::CreateOutput(recvAddress, 1000 * COIN, "test", TokenId(), Scalar::Rand(), blsct::CreateTransactionType::STAKED_COMMITMENT, 999 * COIN);
    coin3.nHeight = 1;
    coin3.out = out3.out;

    auto commitment1 = coin.out.blsctData.rangeProof.Vs[0];
    auto commitment2 = coin2.out.blsctData.rangeProof.Vs[0];
    auto commitment3 = coin3.out.blsctData.rangeProof.Vs[0];

    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());

        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        coins_view_cache.AddCoin(outpoint2, std::move(coin2), true);

        BOOST_CHECK(coins_view_cache.GetStakedCommitments().Exists(commitment1));
        BOOST_CHECK(coins_view_cache.GetStakedCommitments().Exists(commitment2));

        coins_view_cache.SpendCoin(outpoint);

        BOOST_CHECK(!coins_view_cache.GetStakedCommitments().Exists(commitment1));
        BOOST_CHECK(coins_view_cache.GetStakedCommitments().Exists(commitment2));
        BOOST_CHECK(coins_view_cache.Flush());
        BOOST_CHECK(!coins_view_cache.GetStakedCommitments().Exists(commitment1));
        BOOST_CHECK(coins_view_cache.GetStakedCommitments().Exists(commitment2));
    }

    BOOST_CHECK(!base.GetStakedCommitments().Exists(commitment1));
    BOOST_CHECK(base.GetStakedCommitments().Exists(commitment2));

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};

    coins_view_cache.AddCoin(outpoint3, std::move(coin3), true);
    BOOST_CHECK(coins_view_cache.GetStakedCommitments().Exists(commitment3));
    BOOST_CHECK(coins_view_cache.GetStakedCommitments().Exists(commitment2));

    {
        CBlockIndex* index = new CBlockIndex();
        const uint256 randomHash{InsecureRand256()};
        index->phashBlock = &randomHash;
        CBlock block;

        bool fStop = false;

        while (!fStop) {
            block.posProof = blsct::ProofOfStakeLogic::Create(coins_view_cache, out3.value, out3.gamma, index, block, m_node.chainman->GetConsensus());

            if (blsct::ProofOfStakeLogic::Verify(coins_view_cache, index, block, m_node.chainman->GetConsensus()))
                fStop = true;
            else
                block.nTime += 1;
        }

        blsct::ProofOfStakeLogic posProofLogic(block.posProof);

        BOOST_CHECK(posProofLogic.Verify(coins_view_cache, index, block, m_node.chainman->GetConsensus()));

        delete index;
    }
}

BOOST_FIXTURE_TEST_CASE(StakedCommitmentSpendWithMoveoutRemovesFromSet, TestBLSCTChain100Setup)
{
    // Reproduces the bug that left spent staked commitments in the set on the
    // connect path. CCoinsViewCache::UpdateCoins (and DisconnectBlock) call
    // SpendCoin(outpoint, &undo) with moveout non-null. SpendCoin moves the
    // coin out before checking IsStakedCommitment(), so the check runs on a
    // moved-from (empty) CTxOut and RemoveStakedCommitment is never called.
    // Result: an unstake tx spends a commitment but the commitment stays in
    // the set, inflating the set seen by PoS verifiers and breaking the
    // deterministic shuffle agreement between producer and verifier.
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_spend_moveout", .cache_bytes = 1 << 23, .memory_only = true}, {}};
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(wallet.cs_wallet);
    auto blsct_km = wallet.GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    COutPoint outpoint1{Txid::FromUint256(InsecureRand256())};
    COutPoint outpoint2{Txid::FromUint256(InsecureRand256())};
    COutPoint outpoint3{Txid::FromUint256(InsecureRand256())};

    Coin coin1 = CreateCoin(recvAddress);
    Coin coin2 = CreateCoin(recvAddress);
    Coin coin3 = CreateCoin(recvAddress);

    auto commitment1 = coin1.out.blsctData.rangeProof.Vs[0];
    auto commitment2 = coin2.out.blsctData.rangeProof.Vs[0];
    auto commitment3 = coin3.out.blsctData.rangeProof.Vs[0];

    CCoinsViewCache view{&base, /*deterministic=*/true};
    view.SetBestBlock(InsecureRand256());

    view.AddCoin(outpoint1, std::move(coin1), true);
    view.AddCoin(outpoint2, std::move(coin2), true);
    view.AddCoin(outpoint3, std::move(coin3), true);

    BOOST_CHECK_EQUAL(view.GetStakedCommitments().Size(), 3U);
    BOOST_CHECK(view.GetStakedCommitments().Exists(commitment1));
    BOOST_CHECK(view.GetStakedCommitments().Exists(commitment2));
    BOOST_CHECK(view.GetStakedCommitments().Exists(commitment3));

    // This is the exact call shape used by UpdateCoins() on the connect path
    // when an unstake tx consumes a staked-commitment output: the prevout is
    // moved into the tx-undo record via SpendCoin(..., &undo).
    Coin undo1;
    BOOST_CHECK(view.SpendCoin(outpoint1, &undo1));

    // Spent commitment must leave the set.
    BOOST_CHECK_MESSAGE(!view.GetStakedCommitments().Exists(commitment1),
                        "SpendCoin with moveout did not remove commitment1 from set");
    BOOST_CHECK_EQUAL(view.GetStakedCommitments().Size(), 2U);

    // undo captured the original CTxOut (so DisconnectBlock can restore it).
    BOOST_CHECK(undo1.out.IsStakedCommitment());
    BOOST_CHECK(undo1.out.blsctData.rangeProof.Vs[0] == commitment1);

    // A second moveout spend further shrinks the set.
    Coin undo2;
    BOOST_CHECK(view.SpendCoin(outpoint2, &undo2));
    BOOST_CHECK(!view.GetStakedCommitments().Exists(commitment2));
    BOOST_CHECK(view.GetStakedCommitments().Exists(commitment3));
    BOOST_CHECK_EQUAL(view.GetStakedCommitments().Size(), 1U);

    // Flushing to the backing view must persist the removals.
    BOOST_CHECK(view.Flush());
    BOOST_CHECK(!base.GetStakedCommitments().Exists(commitment1));
    BOOST_CHECK(!base.GetStakedCommitments().Exists(commitment2));
    BOOST_CHECK(base.GetStakedCommitments().Exists(commitment3));
    BOOST_CHECK_EQUAL(base.GetStakedCommitments().Size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
