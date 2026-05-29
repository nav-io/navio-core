// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <aggregation/combine.h>

#include <blsct/wallet/keyman.h>
#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/verification.h>
#include <coins.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(aggregation_tests)

namespace {
//! Register a fresh coin owned by `km` worth `amount` in `cache`; return its outpoint.
COutPoint FundCoin(blsct::KeyMan* km, CCoinsViewCache& cache, CAmount amount)
{
    const auto txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint{txid};
    Coin coin;
    auto out = blsct::CreateOutput(std::get<blsct::DoublePublicKey>(km->GetNewDestination(0).value()), amount, "fund");
    coin.nHeight = 1;
    coin.out = out.out;
    cache.AddCoin(outpoint, std::move(coin), true);
    return outpoint;
}

//! Build a fee-0, 1-in-1-out cover "candidate": input == output, no fee.
//! This mirrors a responder's reply; it does NOT verify standalone (it pays no
//! fee) but contributes a valid balance/sig to an aggregate.
CTransactionRef BuildCandidate(blsct::KeyMan* km, CCoinsViewCache& cache,
                               CAmount amount, const blsct::SubAddress& dest)
{
    auto outpoint = FundCoin(km, cache, amount);
    auto f = blsct::TxFactory(km);
    BOOST_REQUIRE(f.AddInput(cache, outpoint));
    f.AddOutput(dest, amount, "candidate", TokenId(), blsct::NORMAL, 0, false, MclScalar::Rand(), /*nBLSCTDefaultFee=*/0);
    auto built = f.BuildTx(/*nBLSCTDefaultFee=*/0);
    BOOST_REQUIRE(built.has_value());
    return MakeTransactionRef(built.value());
}
} // namespace

BOOST_FIXTURE_TEST_CASE(combine_empty_returns_nullopt, TestingSetup)
{
    std::vector<CTransactionRef> none;
    BOOST_CHECK(!aggregation::CombineHalves(none).has_value());
}

BOOST_FIXTURE_TEST_CASE(combine_two_halves_verifies, TestingSetup)
{
    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(wallet->cs_wallet);
    auto km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_REQUIRE(km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};
    CCoinsViewCache cache{&base, /*deterministic=*/true};
    cache.SetBestBlock(InsecureRand256());

    blsct::SubAddress dest(std::get<blsct::DoublePublicKey>(km->GetNewDestination(0).value()));

    // Two fee-0 cover candidates from "responders".
    CTransactionRef c1 = BuildCandidate(km, cache, 300 * COIN, dest);
    CTransactionRef c2 = BuildCandidate(km, cache, 200 * COIN, dest);

    // The initiator's own half pays the fee for the WHOLE aggregate: its own
    // weight plus the two candidates' weight. additionalFee covers the latter.
    const CAmount cand_extra_fee =
        static_cast<CAmount>(blsct::GetTransactionWeight(*c1) + blsct::GetTransactionWeight(*c2)) * BLSCT_DEFAULT_FEE;

    auto own_outpoint = FundCoin(km, cache, 1000 * COIN);
    auto initiator = blsct::TxFactory(km);
    BOOST_REQUIRE(initiator.AddInput(cache, own_outpoint));
    initiator.AddOutput(dest, 900 * COIN, "spend");
    auto own = initiator.BuildTx(BLSCT_DEFAULT_FEE, /*additionalFee=*/cand_extra_fee);
    BOOST_REQUIRE(own.has_value());
    CTransactionRef own_ref = MakeTransactionRef(own.value());

    std::vector<CTransactionRef> halves{own_ref, c1, c2};
    auto combined = aggregation::CombineHalves(halves);
    BOOST_REQUIRE(combined.has_value());

    BOOST_CHECK_EQUAL(combined->vin.size(), own_ref->vin.size() + c1->vin.size() + c2->vin.size());

    // The aggregate verifies as a single BLSCT transaction: balance zeroes per
    // TokenId, exactly one non-zero fee output, fee >= combined-weight minimum.
    TxValidationState sc;
    BOOST_CHECK(blsct::VerifyTx(CTransaction(*combined), cache, sc));
}

BOOST_FIXTURE_TEST_CASE(combine_rejects_duplicate_input, TestingSetup)
{
    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(wallet->cs_wallet);
    auto km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_REQUIRE(km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};
    CCoinsViewCache cache{&base, /*deterministic=*/true};
    cache.SetBestBlock(InsecureRand256());

    blsct::SubAddress dest(std::get<blsct::DoublePublicKey>(km->GetNewDestination(0).value()));
    CTransactionRef a = BuildCandidate(km, cache, 300 * COIN, dest);

    // Feeding the same half twice = the same input twice = rejected.
    std::vector<CTransactionRef> halves{a, a};
    BOOST_CHECK(!aggregation::CombineHalves(halves).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
