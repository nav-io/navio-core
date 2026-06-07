// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <aggregation/combine.h>
#include <aggregation/pool.h>
#include <aggregation/session.h>

#include <blsct/wallet/keyman.h>
#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/verification.h>
#include <coins.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(aggregation_tests)

namespace {
//! Register a fresh coin of `token` owned by `km` worth `amount`; return its outpoint.
COutPoint FundTokenCoin(blsct::KeyMan* km, CCoinsViewCache& cache, CAmount amount, const TokenId& token)
{
    const auto txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint{txid};
    Coin coin;
    auto out = blsct::CreateOutput(std::get<blsct::DoublePublicKey>(km->GetNewDestination(0).value()), amount, "fund", token);
    coin.nHeight = 1;
    coin.out = out.out;
    cache.AddCoin(outpoint, std::move(coin), true);
    return outpoint;
}

//! Register a fresh NAV coin owned by `km` worth `amount` in `cache`; return its outpoint.
COutPoint FundCoin(blsct::KeyMan* km, CCoinsViewCache& cache, CAmount amount)
{
    return FundTokenCoin(km, cache, amount, TokenId());
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

// ---- CandidatePool ----

namespace {
//! A 1-in candidate with a deterministic input outpoint (no real crypto needed
//! for pool bookkeeping tests).
CTransactionRef FakeCandidate(const uint256& input_hash, uint32_t n = 0)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::BLSCT_MARKER;
    mtx.vin.emplace_back(COutPoint(input_hash));
    mtx.vout.emplace_back();
    return MakeTransactionRef(mtx);
}
} // namespace

BOOST_FIXTURE_TEST_CASE(pool_add_dedupe_evict, BasicTestingSetup)
{
    aggregation::CandidatePool pool;
    const uint256 h1 = InsecureRand256();
    const uint256 h2 = InsecureRand256();

    BOOST_CHECK_EQUAL(pool.Size(), 0u);
    BOOST_CHECK(pool.AddCandidate(FakeCandidate(h1), /*peer=*/1));
    BOOST_CHECK_EQUAL(pool.Size(), 1u);
    BOOST_CHECK(pool.Contains(COutPoint(h1)));

    // Same input again -> dedupe rejected, even from a different peer.
    BOOST_CHECK(!pool.AddCandidate(FakeCandidate(h1), /*peer=*/2));
    BOOST_CHECK_EQUAL(pool.Size(), 1u);

    // Distinct input accepted.
    BOOST_CHECK(pool.AddCandidate(FakeCandidate(h2), /*peer=*/1));
    BOOST_CHECK_EQUAL(pool.Size(), 2u);

    // Eviction by input.
    BOOST_CHECK(pool.EvictByInput(COutPoint(h1)));
    BOOST_CHECK_EQUAL(pool.Size(), 1u);
    BOOST_CHECK(!pool.Contains(COutPoint(h1)));
    // Evicting a missing input is a no-op false.
    BOOST_CHECK(!pool.EvictByInput(COutPoint(h1)));
}

BOOST_FIXTURE_TEST_CASE(pool_rejects_multi_input, BasicTestingSetup)
{
    aggregation::CandidatePool pool;
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(InsecureRand256()));
    mtx.vin.emplace_back(COutPoint(InsecureRand256()));
    BOOST_CHECK(!pool.AddCandidate(MakeTransactionRef(mtx), 1));
    BOOST_CHECK_EQUAL(pool.Size(), 0u);
}

BOOST_FIXTURE_TEST_CASE(pool_per_peer_cap, BasicTestingSetup)
{
    aggregation::CandidatePool pool;
    size_t accepted = 0;
    for (size_t i = 0; i < aggregation::POOL_MAX_PER_PEER + 5; ++i) {
        if (pool.AddCandidate(FakeCandidate(InsecureRand256()), /*peer=*/42)) ++accepted;
    }
    BOOST_CHECK_EQUAL(accepted, aggregation::POOL_MAX_PER_PEER);
    BOOST_CHECK_EQUAL(pool.Size(), aggregation::POOL_MAX_PER_PEER);

    // A different peer can still contribute.
    BOOST_CHECK(pool.AddCandidate(FakeCandidate(InsecureRand256()), /*peer=*/43));
}

BOOST_FIXTURE_TEST_CASE(pool_block_connected_evicts, BasicTestingSetup)
{
    aggregation::CandidatePool pool;
    const uint256 h = InsecureRand256();
    BOOST_CHECK(pool.AddCandidate(FakeCandidate(h), 1));

    // A block whose tx spends the candidate's input evicts it.
    auto block = std::make_shared<CBlock>();
    CMutableTransaction spender;
    spender.vin.emplace_back(COutPoint(h));
    block->vtx.push_back(MakeTransactionRef(spender));

    pool.BlockConnected(ChainstateRole::NORMAL, block, nullptr);
    BOOST_CHECK_EQUAL(pool.Size(), 0u);
}

// ---- Pool -> combine bridge (the getp2pmsgaggregate path) ----

BOOST_FIXTURE_TEST_CASE(pool_pick_combine_evict, TestingSetup)
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

    // Two fee-0 cover candidates land in the pool (as if received over the wire).
    aggregation::CandidatePool pool;
    CTransactionRef c1 = BuildCandidate(km, cache, 300 * COIN, dest);
    CTransactionRef c2 = BuildCandidate(km, cache, 200 * COIN, dest);
    BOOST_REQUIRE(pool.AddCandidate(c1, /*peer=*/1));
    BOOST_REQUIRE(pool.AddCandidate(c2, /*peer=*/2));
    BOOST_CHECK_EQUAL(pool.Size(), 2u);

    // The "getp2pmsgaggregate" path: pick candidates, build own over-funding half,
    // combine, then evict the consumed candidates.
    auto picked = pool.PickForAggregate(16);
    BOOST_CHECK_EQUAL(picked.size(), 2u);

    const CAmount extra = aggregation::RequiredCandidateFee(picked, BLSCT_DEFAULT_FEE);
    auto own_outpoint = FundCoin(km, cache, 1000 * COIN);
    auto factory = blsct::TxFactory(km);
    BOOST_REQUIRE(factory.AddInput(cache, own_outpoint));
    factory.AddOutput(dest, 900 * COIN, "spend");
    auto own = factory.BuildTx(BLSCT_DEFAULT_FEE, /*additionalFee=*/extra);
    BOOST_REQUIRE(own.has_value());

    std::vector<CTransactionRef> halves{MakeTransactionRef(own.value())};
    for (const auto& c : picked) halves.push_back(c);
    auto combined = aggregation::CombineHalves(halves);
    BOOST_REQUIRE(combined.has_value());

    TxValidationState st;
    BOOST_CHECK(blsct::VerifyTx(CTransaction(*combined), cache, st));

    // Evict the consumed candidates, as the RPC does after a successful broadcast.
    for (size_t i = 1; i < halves.size(); ++i)
        for (const CTxIn& in : halves[i]->vin) pool.EvictByInput(in.prevout);
    BOOST_CHECK_EQUAL(pool.Size(), 0u);
}

// ---- CANDIDATE_TX wire round-trip ----
// Exercises the exact serialize/deserialize the inbound transport handler uses:
// a candidate is sent as TX_WITH_WITNESS bytes and recovered the same way, then
// added to the pool. Guards against the params-stream pitfall on BLSCT txs.

BOOST_FIXTURE_TEST_CASE(candidate_wire_roundtrip, TestingSetup)
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

    CTransactionRef candidate = BuildCandidate(km, cache, 300 * COIN, dest);

    // Sender side (sendcandidate RPC): serialize with witness params.
    DataStream ss;
    ParamsStream sps{TX_WITH_WITNESS, ss};
    sps << candidate;
    auto bytes = MakeUCharSpan(ss);
    std::vector<uint8_t> body(bytes.begin(), bytes.end());

    // Receiver side (inbound handler): deserialize the same way and add to pool.
    DataStream rs{MakeByteSpan(body)};
    ParamsStream rps{TX_WITH_WITNESS, rs};
    CTransactionRef recovered;
    rps >> recovered;
    BOOST_REQUIRE(recovered != nullptr);
    BOOST_CHECK(recovered->GetHash() == candidate->GetHash());

    aggregation::CandidatePool pool;
    BOOST_CHECK(pool.AddCandidate(recovered, /*peer=*/1));
    BOOST_CHECK_EQUAL(pool.Size(), 1u);
}

// ---- Cross-token swap via unbalanced halves ----

BOOST_FIXTURE_TEST_CASE(swap_unbalanced_halves_combine_verifies, TestingSetup)
{
    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(wallet->cs_wallet);
    auto km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_REQUIRE(km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};
    CCoinsViewCache cache{&base, /*deterministic=*/true};
    cache.SetBestBlock(InsecureRand256());

    const TokenId NAV;                                    // sell token (taker pays)
    const TokenId TOKA(uint256(uint64_t{0xA}));           // buy token (taker receives)
    blsct::SubAddress taker_addr(std::get<blsct::DoublePublicKey>(km->GetNewDestination(0).value()));
    blsct::SubAddress maker_addr(std::get<blsct::DoublePublicKey>(km->GetNewDestination(0).value()));
    blsct::DoublePublicKey taker_change = std::get<blsct::DoublePublicKey>(km->GetNewDestination(0).value());
    blsct::DoublePublicKey maker_change = std::get<blsct::DoublePublicKey>(km->GetNewDestination(0).value());

    const CAmount fill = 1000 * COIN;       // TOKA the taker receives
    const CAmount sell_cost = 50 * COIN;    // NAV the taker pays

    // Maker half: pays TOKA (input >= fill), receives NAV (sell_cost). Maker funds
    // the whole combined fee via an extra NAV-less... no: fee must be NAV. Give the
    // maker a small NAV coin too so it can fund the fee for the whole swap.
    // Taker half first: pays NAV (>= sell_cost), receives TOKA (fill). It pays no
    // fee (rate 0 -> 0-value fee output); the maker funds the whole combined fee.
    auto taker_nav = FundCoin(km, cache, 100 * COIN);
    auto taker = blsct::TxFactory(km);
    BOOST_REQUIRE(taker.AddInput(cache, taker_nav));
    auto taker_half = taker.BuildUnbalancedHalf(taker_change, taker_addr,
                                                /*pay_token=*/NAV, /*pay_amount=*/sell_cost,
                                                /*recv_token=*/TOKA, /*recv_amount=*/fill,
                                                /*nBLSCTDefaultFee=*/0, /*additionalFee=*/0);
    BOOST_REQUIRE(taker_half.has_value());
    const CAmount taker_weight_fee =
        static_cast<CAmount>(blsct::GetTransactionWeight(CTransaction(taker_half.value()))) * BLSCT_DEFAULT_FEE;

    // Maker half: pays TOKA (fill), receives NAV (sell_cost), and over-funds the
    // fee to cover the taker half's weight too. Exactly one non-zero fee output.
    auto maker_toka = FundTokenCoin(km, cache, 1200 * COIN, TOKA);
    auto maker_nav = FundCoin(km, cache, 10 * COIN);
    auto maker = blsct::TxFactory(km);
    BOOST_REQUIRE(maker.AddInput(cache, maker_toka));
    BOOST_REQUIRE(maker.AddInput(cache, maker_nav));
    auto maker_half = maker.BuildUnbalancedHalf(maker_change, maker_addr,
                                                /*pay_token=*/TOKA, /*pay_amount=*/fill,
                                                /*recv_token=*/NAV, /*recv_amount=*/sell_cost,
                                                BLSCT_DEFAULT_FEE,
                                                /*additionalFee=*/taker_weight_fee);
    BOOST_REQUIRE(maker_half.has_value());

    std::vector<CTransactionRef> halves{
        MakeTransactionRef(taker_half.value()),
        MakeTransactionRef(maker_half.value())};
    auto combined = aggregation::CombineHalves(halves);
    BOOST_REQUIRE(combined.has_value());

    // The combined swap balances per TokenId (NAV: taker pays, maker receives;
    // TOKA: maker pays, taker receives) and verifies as one BLSCT transaction.
    TxValidationState st;
    bool ok = blsct::VerifyTx(CTransaction(*combined), cache, st);
    if (!ok) BOOST_TEST_MESSAGE("swap VerifyTx reject: " << st.GetRejectReason());
    BOOST_CHECK(ok);
}

// ---- Session fee math ----

BOOST_FIXTURE_TEST_CASE(session_required_fee, TestingSetup)
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

    CTransactionRef c1 = BuildCandidate(km, cache, 300 * COIN, dest);
    CTransactionRef c2 = BuildCandidate(km, cache, 200 * COIN, dest);
    std::vector<CTransactionRef> cands{c1, c2};

    const int64_t expected_w = blsct::GetTransactionWeight(*c1) + blsct::GetTransactionWeight(*c2);
    BOOST_CHECK_EQUAL(aggregation::SumCandidateWeight(cands), expected_w);
    BOOST_CHECK_EQUAL(aggregation::RequiredCandidateFee(cands, BLSCT_DEFAULT_FEE),
                      static_cast<CAmount>(expected_w) * BLSCT_DEFAULT_FEE);

    // An empty candidate set requires no extra fee.
    std::vector<CTransactionRef> empty;
    BOOST_CHECK_EQUAL(aggregation::RequiredCandidateFee(empty, BLSCT_DEFAULT_FEE), 0);
}

BOOST_AUTO_TEST_SUITE_END()
