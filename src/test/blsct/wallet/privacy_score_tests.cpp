// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/txfactory_global.h>
#include <script/script.h>
#include <streams.h>
#include <wallet/coincontrol.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <wallet/privacy_score.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <bit>
#include <limits>

#include <boost/test/unit_test.hpp>

using namespace wallet;

BOOST_AUTO_TEST_SUITE(blsct_privacy_score_tests)

BOOST_AUTO_TEST_CASE(log2_milli_bits)
{
    BOOST_CHECK_EQUAL(Log2MilliBits(1), 0U);
    BOOST_CHECK_EQUAL(Log2MilliBits(2), 1000U);
    BOOST_CHECK_EQUAL(Log2MilliBits(3), 1584U);
    BOOST_CHECK_EQUAL(Log2MilliBits(4), 2000U);
    BOOST_CHECK_EQUAL(Log2MilliBits(5), 2321U);
    BOOST_CHECK_EQUAL(Log2MilliBits(7), 2807U);
    BOOST_CHECK_EQUAL(Log2MilliBits(8), 3000U);
    BOOST_CHECK_EQUAL(Log2MilliBits(1000), 9965U);
    BOOST_CHECK_EQUAL(Log2MilliBits(uint64_t{1} << 40), 40000U);
    BOOST_CHECK_EQUAL(Log2MilliBits((uint64_t{1} << 40) + 1), 40000U);
    BOOST_CHECK_EQUAL(Log2MilliBits((uint64_t{1} << 41) - 1), 40999U);
    BOOST_CHECK_EQUAL(Log2MilliBits(std::numeric_limits<uint64_t>::max()), 63999U);
    // Monotonic, and within one bit of the power of two below.
    PrivacyMilliBits prev{0};
    for (uint64_t n = 1; n < 5000; ++n) {
        const PrivacyMilliBits v{Log2MilliBits(n)};
        BOOST_CHECK(v >= prev);
        BOOST_CHECK_EQUAL(v / 1000, static_cast<PrivacyMilliBits>(std::bit_width(n) - 1));
        prev = v;
    }
}

BOOST_AUTO_TEST_CASE(compute_privacy_milli_bits)
{
    // Spending none of our coins: a receive, whatever the foreign inputs.
    BOOST_CHECK(ComputePrivacyMilliBits(0, {}) == PrivacyMilliBits{0});
    BOOST_CHECK(ComputePrivacyMilliBits(5, {}) == PrivacyMilliBits{0});
    // Our own send: the lowest of the coins spent.
    BOOST_CHECK(ComputePrivacyMilliBits(0, {3000, 1000, 2000}) == PrivacyMilliBits{1000});
    // Mixed with foreign inputs: log2(foreign + 1) on top of that.
    BOOST_CHECK(ComputePrivacyMilliBits(1, {0}) == PrivacyMilliBits{1000});
    BOOST_CHECK(ComputePrivacyMilliBits(3, {1000, 4000}) == PrivacyMilliBits{3000});
    BOOST_CHECK(ComputePrivacyMilliBits(2, {1000}) == PrivacyMilliBits{2584});
    // One unknown own input makes the result unknown.
    BOOST_CHECK(ComputePrivacyMilliBits(0, {1000, std::nullopt}) == std::nullopt);
    BOOST_CHECK(ComputePrivacyMilliBits(7, {std::nullopt}) == std::nullopt);
    // Saturates below the unknown encoding.
    BOOST_CHECK(ComputePrivacyMilliBits(1, {PRIVACY_MILLI_BITS_MAX}) == PRIVACY_MILLI_BITS_MAX);
    BOOST_CHECK(ComputePrivacyMilliBits(1, {PRIVACY_MILLI_BITS_MAX - 10}) == PRIVACY_MILLI_BITS_MAX);
    BOOST_CHECK(ComputePrivacyMilliBits(std::numeric_limits<uint64_t>::max(), {0}) == PrivacyMilliBits{63999});
}

BOOST_AUTO_TEST_CASE(privacy_bits_univalue)
{
    BOOST_CHECK(PrivacyBitsToUniValue(std::nullopt).isNull());
    BOOST_CHECK_EQUAL(PrivacyBitsToUniValue(PrivacyMilliBits{0}).write(), "0.000");
    BOOST_CHECK_EQUAL(PrivacyBitsToUniValue(PrivacyMilliBits{1584}).write(), "1.584");
    BOOST_CHECK_EQUAL(PrivacyBitsToUniValue(PrivacyMilliBits{12005}).write(), "12.005");
    BOOST_CHECK_EQUAL(PrivacyBitsToUniValue(PrivacyMilliBits{1584}).get_real(), 1.584);
}

BOOST_FIXTURE_TEST_CASE(wallet_output_score_serialization, BasicTestingSetup)
{
    CWalletOutput wout(std::make_shared<const CTxOut>(), TxStateInactive{});
    wout.fCoverReturn = true;
    for (const std::optional<PrivacyMilliBits> score : {std::optional<PrivacyMilliBits>{}, std::optional<PrivacyMilliBits>{0}, std::optional<PrivacyMilliBits>{2584}}) {
        wout.m_privacy_milli_bits = score;
        DataStream ss{};
        ss << wout;
        CWalletOutput read(std::make_shared<const CTxOut>(), TxStateInactive{});
        ss >> read;
        BOOST_CHECK(read.m_privacy_milli_bits == score);
        BOOST_CHECK(read.fCoverReturn);
    }

    // A row written before scores were recorded ends at fCoverReturn: its
    // score is unknown, and everything else still reads.
    wout.m_privacy_milli_bits = 1000;
    DataStream ss{};
    ss << wout;
    std::vector<std::byte> old_row{ss.begin(), ss.end() - sizeof(PrivacyMilliBits)};
    DataStream old_ss{old_row};
    CWalletOutput read(std::make_shared<const CTxOut>(), TxStateInactive{});
    old_ss >> read;
    BOOST_CHECK(read.m_privacy_milli_bits == std::nullopt);
    BOOST_CHECK(read.fCoverReturn);
}

BOOST_FIXTURE_TEST_CASE(wallet_tx_score_serialization, BasicTestingSetup)
{
    CMutableTransaction mtx;
    mtx.nVersion |= CTransaction::BLSCT_MARKER;
    mtx.vin.emplace_back(COutPoint{uint256::ONE});
    mtx.vout.assign(3, CTxOut{1 * COIN, CScript{} << OP_TRUE});
    CWalletTx wtx(MakeTransactionRef(mtx), TxStateInactive{});
    wtx.mapValue["comment"] = "kept";

    // No scores: no entry, and every output reads back unknown.
    {
        DataStream ss{};
        ss << wtx;
        CWalletTx read(nullptr, TxStateInactive{});
        ss >> read;
        BOOST_CHECK(read.m_privacy_milli_bits.empty());
        BOOST_CHECK(read.GetPrivacyMilliBits(0) == std::nullopt);
    }

    wtx.m_privacy_milli_bits = {{0, 0}, {2, 3584}};
    DataStream ss{};
    ss << wtx;
    CWalletTx read(nullptr, TxStateInactive{});
    ss >> read;
    BOOST_CHECK(read.m_privacy_milli_bits == wtx.m_privacy_milli_bits);
    BOOST_CHECK(read.GetPrivacyMilliBits(0) == PrivacyMilliBits{0});
    BOOST_CHECK(read.GetPrivacyMilliBits(1) == std::nullopt);
    BOOST_CHECK(read.GetPrivacyMilliBits(2) == PrivacyMilliBits{3584});
    // The entry is internal: it does not show among the user's values.
    BOOST_CHECK(!read.mapValue.contains("privbits"));
    BOOST_CHECK_EQUAL(read.mapValue.at("comment"), "kept");

    // A malformed entry is skipped, not a load failure.
    CWalletTx bad(MakeTransactionRef(mtx), TxStateInactive{});
    bad.mapValue["privbits"] = "x:1,1:2:3,1:5,2:4294967295";
    DataStream bad_ss{};
    bad_ss << bad;
    CWalletTx bad_read(nullptr, TxStateInactive{});
    bad_ss >> bad_read;
    BOOST_CHECK(bad_read.m_privacy_milli_bits == (std::map<uint32_t, PrivacyMilliBits>{{1, 5}}));
}

namespace {
//! A BLSCT wallet, with output storage or full transactions, and helpers to
//! sync transactions into it as the mempool callback does.
struct ScoreWallet {
    std::shared_ptr<CWallet> wallet;
    blsct::KeyMan* km{nullptr};
    blsct::DoublePublicKey receive;
    blsct::DoublePublicKey change;
    bool storage;

    ScoreWallet(interfaces::Chain* chain, bool output_storage) : storage{output_storage}
    {
        wallet = std::make_shared<CWallet>(chain, "", CreateMockableWalletDatabase());
        wallet->InitWalletFlags(WALLET_FLAG_BLSCT | (output_storage ? WALLET_FLAG_BLSCT_OUTPUT_STORAGE : 0));
        LOCK(wallet->cs_wallet);
        km = wallet->GetOrCreateBLSCTKeyMan();
        BOOST_REQUIRE(km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
        wallet->SetLastBlockProcessed(1, InsecureRand256());
        receive = std::get<blsct::DoublePublicKey>(km->GetNewDestination(0).value());
        change = std::get<blsct::DoublePublicKey>(km->GetNewDestination(blsct::CHANGE_ACCOUNT).value());
    }

    static CTransactionRef MakeTx(const std::vector<COutPoint>& ins, size_t foreign_ins, const std::vector<CTxOut>& outs)
    {
        CMutableTransaction mtx;
        mtx.nVersion |= CTransaction::BLSCT_MARKER;
        for (const COutPoint& in : ins) mtx.vin.emplace_back(in);
        for (size_t i = 0; i < foreign_ins; ++i) mtx.vin.emplace_back(COutPoint{InsecureRand256()});
        mtx.vout = outs;
        return MakeTransactionRef(mtx);
    }

};
} // namespace

static std::optional<PrivacyMilliBits> Score(const CWallet& wallet, const CTxOut& out) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    return wallet.GetCoinPrivacyMilliBits(COutPoint{out.GetHash()});
}

//! The score listed for `out` among the wallet's available coins.
static std::optional<PrivacyMilliBits> ListedScore(CWallet& wallet, bool storage, const CTxOut& out) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (!storage) {
        // A full-tx wallet lists a mempool coin only while the node's
        // mempool has its tx, which these synthetic txs never reach.
        CWalletTx& wtx = wallet.mapWallet.at(Assert(wallet.GetWalletTxFromOutpoint(COutPoint{out.GetHash()}))->GetHash());
        wtx.m_state = TxStateConfirmed{InsecureRand256(), 1, 0};
        wtx.MarkDirty();
    }
    CCoinControl cc;
    cc.m_include_unsafe_inputs = true;
    cc.m_min_depth = 0;
    CoinFilterParams params;
    params.only_spendable = false;
    const auto coins{(storage ? AvailableBlsctCoins(wallet, &cc, params) : AvailableCoins(wallet, &cc, std::nullopt, params)).All()};
    for (const COutput& coin : coins) {
        if (coin.outpoint == COutPoint{out.GetHash()}) return coin.privacy_milli_bits;
    }
    BOOST_FAIL("coin not listed");
    return std::nullopt;
}

static void CheckSyncedScores(interfaces::Chain* chain, bool output_storage)
{
    ScoreWallet w(chain, output_storage);
    CWallet& wallet = *w.wallet;
    LOCK(wallet.cs_wallet);

    // A coin paid to us by someone else scores 0.
    const CTxOut coin_a{blsct::CreateOutput(w.receive, 50 * COIN, "a").out};
    const CTxOut coin_b{blsct::CreateOutput(w.receive, 30 * COIN, "b").out};
    wallet.transactionAddedToMempool(ScoreWallet::MakeTx({}, 2, {coin_a, coin_b}));
    BOOST_CHECK(Score(wallet, coin_a) == PrivacyMilliBits{0});
    BOOST_CHECK(Score(wallet, coin_b) == PrivacyMilliBits{0});

    // Our coin mixed with three foreign inputs: our change scores
    // log2(3 + 1) = 2 bits, and so does a payment to our receive address in
    // the same tx, though a foreign input's owner may have made it.
    const CTxOut change_a{blsct::CreateOutput(w.change, 49 * COIN, "").out};
    const CTxOut paid_in_mix{blsct::CreateOutput(w.receive, 7 * COIN, "").out};
    const CTransactionRef mix{ScoreWallet::MakeTx({COutPoint{coin_a.GetHash()}}, 3, {change_a, paid_in_mix})};
    wallet.transactionAddedToMempool(mix);
    BOOST_CHECK(Score(wallet, change_a) == PrivacyMilliBits{2000});
    BOOST_CHECK(Score(wallet, paid_in_mix) == PrivacyMilliBits{2000});
    BOOST_CHECK(ListedScore(wallet, w.storage, change_a) == PrivacyMilliBits{2000});

    // A send of ours (no foreign inputs) scores the lowest of its inputs,
    // every output alike.
    const CTxOut change_ab{blsct::CreateOutput(w.change, 60 * COIN, "").out};
    const CTxOut to_self{blsct::CreateOutput(w.receive, 18 * COIN, "").out};
    wallet.transactionAddedToMempool(ScoreWallet::MakeTx({COutPoint{change_a.GetHash()}, COutPoint{coin_b.GetHash()}}, 0, {change_ab, to_self}));
    BOOST_CHECK(Score(wallet, change_ab) == PrivacyMilliBits{0});
    BOOST_CHECK(Score(wallet, to_self) == PrivacyMilliBits{0});

    // Our coin served as a cover candidate comes back, on its (receive)
    // address with its amount and the cover memo, out of someone's aggregate
    // with one foreign input: 0 + log2(1 + 1). A payment to the same address
    // in that aggregate, not a return, scores the same.
    const CTxOut cover_back{blsct::CreateOutput(w.receive, 18 * COIN, std::string{blsct::COVER_CANDIDATE_MEMO}).out};
    const CTxOut paid_in_aggregate{blsct::CreateOutput(w.receive, 3 * COIN, "").out};
    wallet.transactionAddedToMempool(ScoreWallet::MakeTx({COutPoint{to_self.GetHash()}}, 1, {paid_in_aggregate, cover_back}));
    BOOST_CHECK(Score(wallet, cover_back) == PrivacyMilliBits{1000});
    BOOST_CHECK(Score(wallet, paid_in_aggregate) == PrivacyMilliBits{1000});

    // Served again, with three foreign inputs: 1 + log2(3 + 1) bits, for the
    // returned cover and for a payment to us inside that aggregate alike.
    const CTxOut cover_back2{blsct::CreateOutput(w.receive, 18 * COIN, std::string{blsct::COVER_CANDIDATE_MEMO}).out};
    const CTxOut paid_in_aggregate2{blsct::CreateOutput(w.receive, 2 * COIN, "").out};
    wallet.transactionAddedToMempool(ScoreWallet::MakeTx({COutPoint{cover_back.GetHash()}}, 3, {paid_in_aggregate2, cover_back2}));
    BOOST_CHECK(Score(wallet, cover_back2) == PrivacyMilliBits{3000});
    BOOST_CHECK(Score(wallet, paid_in_aggregate2) == PrivacyMilliBits{3000});
    BOOST_CHECK(ListedScore(wallet, w.storage, cover_back2) == PrivacyMilliBits{3000});

    // A tx seen again in another form (a block tx the staker merged it into,
    // with more foreign inputs) rescores the same output.
    const CTxOut change_c{blsct::CreateOutput(w.change, 10 * COIN, "").out};
    const CTransactionRef own_send{ScoreWallet::MakeTx({COutPoint{change_ab.GetHash()}}, 0, {change_c})};
    wallet.transactionAddedToMempool(own_send);
    BOOST_CHECK(Score(wallet, change_c) == PrivacyMilliBits{0});
    if (output_storage) {
        // The full-tx wallet keeps scores per wallet tx, so the same output
        // in a merged block tx is scored on that tx's own record instead.
        wallet.transactionAddedToMempool(ScoreWallet::MakeTx({COutPoint{change_ab.GetHash()}}, 7, {change_c}));
        BOOST_CHECK(Score(wallet, change_c) == PrivacyMilliBits{3000});
        wallet.transactionAddedToMempool(own_send);
        BOOST_CHECK(Score(wallet, change_c) == PrivacyMilliBits{0});
    }

    // A coin stored without a score (synced before scores were recorded)
    // makes every coin spending it unknown, until a rescan rescores it.
    const CTxOut legacy{blsct::CreateOutput(w.receive, 5 * COIN, "legacy").out};
    const CTransactionRef legacy_tx{ScoreWallet::MakeTx({}, 1, {legacy})};
    wallet.transactionAddedToMempool(legacy_tx);
    if (output_storage) {
        wallet.mapOutputs.at(COutPoint{legacy.GetHash()}).m_privacy_milli_bits.reset();
    } else {
        wallet.mapWallet.at(legacy_tx->GetHash()).m_privacy_milli_bits.clear();
    }
    BOOST_CHECK(Score(wallet, legacy) == std::nullopt);
    BOOST_CHECK(ListedScore(wallet, w.storage, legacy) == std::nullopt);
    const CTxOut legacy_change{blsct::CreateOutput(w.change, 4 * COIN, "").out};
    const CTransactionRef spend_legacy{ScoreWallet::MakeTx({COutPoint{legacy.GetHash()}, COutPoint{change_c.GetHash()}}, 0, {legacy_change})};
    wallet.transactionAddedToMempool(spend_legacy);
    BOOST_CHECK(Score(wallet, legacy_change) == std::nullopt);
    // Re-syncing in chain order, as a rescan does, fills both in.
    wallet.transactionAddedToMempool(legacy_tx);
    wallet.transactionAddedToMempool(spend_legacy);
    BOOST_CHECK(Score(wallet, legacy) == PrivacyMilliBits{0});
    BOOST_CHECK(Score(wallet, legacy_change) == PrivacyMilliBits{0});
}

BOOST_FIXTURE_TEST_CASE(synced_scores_output_storage, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CheckSyncedScores(m_node.chain.get(), /*output_storage=*/true);
}

BOOST_FIXTURE_TEST_CASE(synced_scores_full_tx, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CheckSyncedScores(m_node.chain.get(), /*output_storage=*/false);
}

//! A send the wallet commits scores its change at once, before any sync.
BOOST_FIXTURE_TEST_CASE(committed_send_scores_change, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    for (const bool storage : {true, false}) {
        ScoreWallet w(m_node.chain.get(), storage);
        CWallet& wallet = *w.wallet;
        LOCK(wallet.cs_wallet);
        wallet.SetBroadcastTransactions(false);
        const CTxOut coin{blsct::CreateOutput(w.receive, 50 * COIN, "a").out};
        wallet.transactionAddedToMempool(ScoreWallet::MakeTx({}, 1, {coin}));
        const CTxOut change{blsct::CreateOutput(w.change, 40 * COIN, "").out};
        wallet.CommitTransaction(ScoreWallet::MakeTx({COutPoint{coin.GetHash()}}, 1, {change}), {}, {});
        BOOST_CHECK(Score(wallet, change) == PrivacyMilliBits{1000});
    }
}

BOOST_AUTO_TEST_CASE(select_from_one_privacy_bucket)
{
    using Coins = std::vector<std::pair<CAmount, std::optional<PrivacyMilliBits>>>;
    using Picked = std::optional<std::vector<size_t>>;
    // In selection order (largest first): 10 @ 3.0 bits, 6 @ 0.5, 5 @ 0.9,
    // 4 unknown, 2 @ 3.7.
    const Coins coins{{10, 3000}, {6, 500}, {5, 900}, {4, std::nullopt}, {2, 3700}};
    // The unknown bucket is lowest, but 4 does not exceed 4.
    BOOST_CHECK(SelectFromOnePrivacyBucket(coins, 3) == Picked({3}));
    BOOST_CHECK(SelectFromOnePrivacyBucket(coins, 4) == Picked({1}));
    // Within the bucket, in the given order until the limit is exceeded.
    BOOST_CHECK(SelectFromOnePrivacyBucket(coins, 6) == Picked({1, 2}));
    BOOST_CHECK(SelectFromOnePrivacyBucket(coins, 10) == Picked({1, 2}));
    // Only bucket 3 (10 + 2) can fund 11.
    BOOST_CHECK(SelectFromOnePrivacyBucket(coins, 11) == Picked({0, 4}));
    // No bucket can fund 12 alone.
    BOOST_CHECK(SelectFromOnePrivacyBucket(coins, 12) == std::nullopt);
    BOOST_CHECK(SelectFromOnePrivacyBucket({}, 0) == std::nullopt);
    BOOST_CHECK(SelectFromOnePrivacyBucket(coins, MAX_MONEY) == std::nullopt);
}

BOOST_AUTO_TEST_SUITE_END()
