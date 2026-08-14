// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/verification.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <wallet/receive.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(blsct_txfactory_tests)

static CAmount GetFeeValue(const CTransaction& tx)
{
    for (const auto& vout : tx.vout) {
        if (vout.scriptPubKey.IsFee()) return vout.nValue;
    }
    return 0;
}

static std::optional<size_t> FindOutputIndex(const CMutableTransaction& tx, const uint256& outputHash)
{
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (tx.vout[i].GetHash() == outputHash) return i;
    }
    return std::nullopt;
}

BOOST_FIXTURE_TEST_CASE(ismine_test, TestingSetup)
{
    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    auto out = blsct::CreateOutput(recvAddress, 1000, "test");
    BOOST_CHECK(blsct_km->IsMine(out.out));

    auto hashId = blsct_km->GetHashId(out.out);
    blsct::SubAddress subAddressId;

    BOOST_CHECK(blsct_km->GetSubAddress(hashId, subAddressId));

    auto result = blsct_km->RecoverOutputs({out.out});

    BOOST_CHECK(result.is_completed);
    auto xs = result.amounts;
    BOOST_CHECK(xs.size() == 1);
    BOOST_CHECK(xs[0].amount == 1000);
    BOOST_CHECK(xs[0].message == "test");
}

BOOST_FIXTURE_TEST_CASE(createtransaction_test, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    wallet::CWallet* wallet(new wallet::CWallet(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase()));
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    const auto txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint{txid};

    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    coin.nHeight = 1;
    coin.out = out.out;

    auto tx = blsct::TxFactory(blsct_km);
    TxValidationState tx_state;

    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    BOOST_CHECK(tx.AddInput(coins_view_cache, outpoint));

    tx.AddOutput(recvAddress, 900 * COIN, "test");

    auto finalTx = tx.BuildTx();

    BOOST_CHECK(finalTx.has_value());
    BOOST_CHECK(blsct::VerifyTx(CTransaction(finalTx->tx), coins_view_cache, tx_state));
    const CAmount fee = GetFeeValue(CTransaction(finalTx->tx));
    const CAmount expected_change = 1000 * COIN - 900 * COIN - fee;
    BOOST_REQUIRE(fee > 0);

    bool fFoundChange = false;

    // Wallet does not have the coins available yet
    BOOST_CHECK(blsct::TxFactory::CreateTransaction(wallet, wallet->GetOrCreateBLSCTKeyMan(), blsct::CreateTransactionData{recvAddress, 900 * COIN, "test"}) == std::nullopt);

    auto result = blsct_km->RecoverOutputs(finalTx->tx.vout);

    for (auto& res : result.amounts) {
        if (res.message == "Change" && res.amount == expected_change) fFoundChange = true;
    }

    BOOST_CHECK(fFoundChange);

    wallet->transactionAddedToMempool(MakeTransactionRef(finalTx->tx));

    // Wallet does not have the coins available yet (not confirmed in block)
    BOOST_CHECK(blsct::TxFactory::CreateTransaction(wallet, wallet->GetOrCreateBLSCTKeyMan(), blsct::CreateTransactionData{recvAddress, 900 * COIN, "test"}) == std::nullopt);
}

BOOST_FIXTURE_TEST_CASE(createtransaction_subtractfee_test, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_sffa", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    wallet::CWallet* wallet(new wallet::CWallet(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase()));
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    const auto txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint{txid};

    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    coin.nHeight = 1;
    coin.out = out.out;

    auto tx = blsct::TxFactory(blsct_km);
    TxValidationState tx_state;

    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    BOOST_CHECK(tx.AddInput(coins_view_cache, outpoint));

    // Send 900, subtracting the fee from the recipient's amount.
    tx.AddOutput(recvAddress, 900 * COIN, "test", TokenId(), blsct::NORMAL, 0, /*fSubtractFeeFromAmount=*/true);

    auto finalTx = tx.BuildTx();

    BOOST_REQUIRE(finalTx.has_value());
    BOOST_CHECK(blsct::VerifyTx(CTransaction(finalTx->tx), coins_view_cache, tx_state));

    const CAmount fee = GetFeeValue(CTransaction(finalTx->tx));
    BOOST_REQUIRE(fee > 0);

    // subtract-fee semantics: the recipient bears the fee (receives
    // amount - fee), and the change is exactly inputs - requested amount,
    // independent of the fee -- i.e. the wallet spends exactly the requested
    // amount. (Without the flag the recipient would receive the full 900 and
    // the change would be 100 - fee.)
    auto result = blsct_km->RecoverOutputs(finalTx->tx.vout);
    bool foundRecipient = false;
    bool foundChange = false;
    for (auto& res : result.amounts) {
        if (res.message == "test") {
            foundRecipient = true;
            BOOST_CHECK_EQUAL(res.amount, 900 * COIN - fee);
        }
        if (res.message == "Change") {
            foundChange = true;
            BOOST_CHECK_EQUAL(res.amount, 1000 * COIN - 900 * COIN);
        }
    }
    BOOST_CHECK(foundRecipient);
    BOOST_CHECK(foundChange);
}

// A subtract-fee recipient alongside an ordinary one. The deferred recipient is
// materialized once the fee is known, and that materialization must ADD to the
// token's output total rather than replace it -- the ordinary output's amount is
// already in there. Replacing it makes input selection and change work from a
// total that is short by the other output, so the committed outputs no longer
// balance against the inputs and the transaction cannot verify.
//
// Reachable through the external API, whose `build_ctx` takes a list of
// BlsctTxOut and lets any one of them set subtract_fee_from_amount.
BOOST_FIXTURE_TEST_CASE(createtransaction_subtractfee_with_other_output_test, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_sffa_other", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    COutPoint outpoint{Txid::FromUint256(InsecureRand256())};
    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        Coin coin;
        coin.nHeight = 1;
        coin.out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test").out;
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    auto tx = blsct::TxFactory(blsct_km);
    BOOST_CHECK(tx.AddInput(coins_view_cache, outpoint));

    tx.AddOutput(recvAddress, 100 * COIN, "plain");
    tx.AddOutput(recvAddress, 800 * COIN, "sffa", TokenId(), blsct::NORMAL, 0, /*fSubtractFeeFromAmount=*/true);

    auto finalTx = tx.BuildTx();
    BOOST_REQUIRE(finalTx.has_value());

    TxValidationState tx_state;
    BOOST_CHECK(blsct::VerifyTx(CTransaction(finalTx->tx), coins_view_cache, tx_state));

    const CAmount fee = GetFeeValue(CTransaction(finalTx->tx));
    BOOST_REQUIRE(fee > 0);

    // The plain output is paid in full, the deferred one bears the whole fee,
    // and the change is what is left of the input once both are paid.
    auto result = blsct_km->RecoverOutputs(finalTx->tx.vout);
    bool foundPlain = false;
    bool foundSffa = false;
    bool foundChange = false;
    CAmount recovered = 0;
    for (auto& res : result.amounts) {
        recovered += res.amount;
        if (res.message == "plain") {
            foundPlain = true;
            BOOST_CHECK_EQUAL(res.amount, 100 * COIN);
        }
        if (res.message == "sffa") {
            foundSffa = true;
            BOOST_CHECK_EQUAL(res.amount, 800 * COIN - fee);
        }
        if (res.message == "Change") {
            foundChange = true;
            BOOST_CHECK_EQUAL(res.amount, 1000 * COIN - 100 * COIN - 800 * COIN);
        }
    }
    BOOST_CHECK(foundPlain);
    BOOST_CHECK(foundSffa);
    BOOST_CHECK(foundChange);
    // Everything the input carried is accounted for by the recovered outputs
    // plus the explicit fee output.
    BOOST_CHECK_EQUAL(recovered + fee, 1000 * COIN);
}

// subtract-fee "send everything": the recipient gets the whole input minus the
// fee and there is no change output. This is the same shape the `consolidate`
// RPC builds (one output back to self, fee taken from the merged amount), so it
// guards that path too.
BOOST_FIXTURE_TEST_CASE(createtransaction_subtractfee_sendmax_test, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_sffa_max", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    wallet::CWallet* wallet(new wallet::CWallet(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase()));
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    const auto txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint{txid};

    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    coin.nHeight = 1;
    coin.out = out.out;

    auto tx = blsct::TxFactory(blsct_km);
    TxValidationState tx_state;

    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    BOOST_CHECK(tx.AddInput(coins_view_cache, outpoint));

    // Send the entire input, subtracting the fee: no change output can exist.
    tx.AddOutput(recvAddress, 1000 * COIN, "test", TokenId(), blsct::NORMAL, 0, /*fSubtractFeeFromAmount=*/true);

    auto finalTx = tx.BuildTx();

    BOOST_REQUIRE(finalTx.has_value());
    BOOST_CHECK(blsct::VerifyTx(CTransaction(finalTx->tx), coins_view_cache, tx_state));

    const CAmount fee = GetFeeValue(CTransaction(finalTx->tx));
    BOOST_REQUIRE(fee > 0);

    auto result = blsct_km->RecoverOutputs(finalTx->tx.vout);
    bool foundRecipient = false;
    for (auto& res : result.amounts) {
        if (res.message == "test") {
            foundRecipient = true;
            BOOST_CHECK_EQUAL(res.amount, 1000 * COIN - fee);
        }
        // There must be no change output.
        BOOST_CHECK(res.message != "Change");
    }
    BOOST_CHECK(foundRecipient);
}

// BuildTx randomises vout order, so the recipient output sits at no fixed
// position. The factory must say which output pays the destination: callers
// hand that hash out as the payment handle, and pointing it at the change --
// or at the fee output, which block aggregation merges away and which
// therefore never appears on chain -- silently tracks the wrong money.
BOOST_FIXTURE_TEST_CASE(buildtx_reports_recipient_output_test, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_recipient", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    const auto txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint{txid};

    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    coin.nHeight = 1;
    coin.out = out.out;

    auto tx = blsct::TxFactory(blsct_km);

    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    BOOST_CHECK(tx.AddInput(coins_view_cache, outpoint));

    tx.AddOutput(recvAddress, 900 * COIN, "memo-to-recipient");

    auto finalTx = tx.BuildTx();
    BOOST_REQUIRE(finalTx.has_value());

    // The reported hash must belong to this transaction, and never to the fee
    // output.
    const auto recipientIndex = FindOutputIndex(finalTx->tx, finalTx->recipientOutputHash);
    BOOST_REQUIRE(recipientIndex.has_value());
    BOOST_CHECK(!finalTx->tx.vout[*recipientIndex].scriptPubKey.IsFee());

    // It is the output carrying the recipient's memo and the requested amount
    // -- not the "Change" output.
    auto result = blsct_km->RecoverOutputs(finalTx->tx.vout);
    bool checkedRecipient = false;
    for (auto& res : result.amounts) {
        if (res.id != *recipientIndex) continue;
        checkedRecipient = true;
        BOOST_CHECK_EQUAL(res.message, "memo-to-recipient");
        BOOST_CHECK_EQUAL(res.amount, 900 * COIN);
    }
    BOOST_CHECK(checkedRecipient);
}

// Same guarantee with subtractfeefromamount, where the recipient output is
// built last and appended AFTER the change output: the recipient was not even
// at pre-shuffle vout[0], so a positional recovery reports the change output
// every time.
BOOST_FIXTURE_TEST_CASE(buildtx_reports_recipient_output_subtractfee_test, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_recipient_sffa", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    const auto txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint{txid};

    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    coin.nHeight = 1;
    coin.out = out.out;

    auto tx = blsct::TxFactory(blsct_km);

    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    BOOST_CHECK(tx.AddInput(coins_view_cache, outpoint));

    tx.AddOutput(recvAddress, 900 * COIN, "memo-to-recipient", TokenId(), blsct::NORMAL, 0, /*fSubtractFeeFromAmount=*/true);

    auto finalTx = tx.BuildTx();
    BOOST_REQUIRE(finalTx.has_value());

    const CAmount fee = GetFeeValue(CTransaction(finalTx->tx));
    BOOST_REQUIRE(fee > 0);

    const auto recipientIndex = FindOutputIndex(finalTx->tx, finalTx->recipientOutputHash);
    BOOST_REQUIRE(recipientIndex.has_value());
    BOOST_CHECK(!finalTx->tx.vout[*recipientIndex].scriptPubKey.IsFee());

    // The recipient bears the fee, so it is the output holding (amount - fee).
    // The change output holds the full 100 COIN and must not be reported.
    auto result = blsct_km->RecoverOutputs(finalTx->tx.vout);
    bool checkedRecipient = false;
    for (auto& res : result.amounts) {
        if (res.id != *recipientIndex) continue;
        checkedRecipient = true;
        BOOST_CHECK_EQUAL(res.message, "memo-to-recipient");
        BOOST_CHECK_EQUAL(res.amount, 900 * COIN - fee);
    }
    BOOST_CHECK(checkedRecipient);
}

BOOST_FIXTURE_TEST_CASE(addinput_test, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    const auto txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint{txid};

    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    coin.nHeight = 1;
    coin.out = out.out;

    auto tx = blsct::TxFactory(blsct_km);

    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    BOOST_CHECK(tx.AddInput(coins_view_cache, outpoint));

    tx.AddOutput(recvAddress, 900 * COIN, "test");

    auto finalTx = tx.BuildTx();
    TxValidationState tx_state;

    BOOST_CHECK(finalTx.has_value());
    BOOST_CHECK(blsct::VerifyTx(CTransaction(finalTx->tx), coins_view_cache, tx_state));
    const CAmount first_fee = GetFeeValue(CTransaction(finalTx->tx));
    const CAmount expected_change = 1000 * COIN - 900 * COIN - first_fee;
    BOOST_REQUIRE(first_fee > 0);

    bool fFoundChange = false;
    uint32_t nChangePosition = 0;

    auto result = blsct_km->RecoverOutputs(finalTx->tx.vout);

    for (auto& res : result.amounts) {
        if (res.message == "Change" && res.amount == expected_change) {
            fFoundChange = true;
            nChangePosition = res.id;
        }
    }

    BOOST_CHECK(fFoundChange);

    wallet->transactionAddedToMempool(MakeTransactionRef(finalTx->tx));

    auto wtx = wallet->GetWalletTx(finalTx->tx.GetHash());
    BOOST_CHECK(wtx != nullptr);

    fFoundChange = false;

    if (wtx->GetBLSCTRecoveryData(nChangePosition).message == "Change" && wtx->GetBLSCTRecoveryData(nChangePosition).amount == expected_change) {
        fFoundChange = true;
    }

    BOOST_CHECK(fFoundChange);

    auto tx2 = blsct::TxFactory(blsct_km);
    auto outpoint2 = COutPoint(finalTx->tx.vout[nChangePosition].GetHash());
    Coin coin2;
    coin2.nHeight = 1;
    coin2.out = finalTx->tx.vout[nChangePosition];
    coins_view_cache.AddCoin(outpoint2, std::move(coin2), true);

    BOOST_CHECK(tx2.AddInput(coins_view_cache, outpoint2));

    blsct::SubAddress randomAddress(blsct::DoublePublicKey(MclG1Point::MapToPoint("test1"), MclG1Point::MapToPoint("test2")));
    tx2.AddOutput(randomAddress, 50 * COIN, "test");

    auto finalTx2 = tx2.BuildTx();
    BOOST_REQUIRE(finalTx2.has_value());
    wallet->transactionAddedToMempool(MakeTransactionRef(finalTx2->tx));
    const CAmount second_fee = GetFeeValue(CTransaction(finalTx2->tx));
    BOOST_REQUIRE(second_fee > 0);

    BOOST_CHECK(wallet->GetDebit(CTransaction(finalTx2->tx), wallet::ISMINE_SPENDABLE_BLSCT) == expected_change);
    BOOST_CHECK(TxGetCredit(*wallet, CTransaction(finalTx2->tx), wallet::ISMINE_SPENDABLE_BLSCT) == expected_change - 50 * COIN - second_fee);
}

BOOST_FIXTURE_TEST_CASE(coin_selection_largest_first_test, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_sel", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    // A wallet full of small outputs (e.g. PoS staking rewards) plus one large
    // output. Selecting in insertion order would pile in the small ones; the
    // factory must instead pick the single large output that covers the send.
    std::vector<COutPoint> smallOutpoints;
    COutPoint bigOutpoint;
    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        for (int i = 0; i < 20; ++i) {
            COutPoint op{Txid::FromUint256(InsecureRand256())};
            Coin c;
            c.nHeight = 1;
            c.out = blsct::CreateOutput(recvAddress, 1 * COIN, "small").out;
            coins_view_cache.AddCoin(op, std::move(c), true);
            smallOutpoints.push_back(op);
        }
        bigOutpoint = COutPoint{Txid::FromUint256(InsecureRand256())};
        Coin big;
        big.nHeight = 1;
        big.out = blsct::CreateOutput(recvAddress, 1000 * COIN, "big").out;
        coins_view_cache.AddCoin(bigOutpoint, std::move(big), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    auto tx = blsct::TxFactory(blsct_km);

    // Add the small inputs first and the large one last, so a naive in-order
    // selection would prefer the small ones.
    for (const auto& op : smallOutpoints)
        BOOST_CHECK(tx.AddInput(coins_view_cache, op));
    BOOST_CHECK(tx.AddInput(coins_view_cache, bigOutpoint));

    blsct::SubAddress randomAddress(blsct::DoublePublicKey(MclG1Point::MapToPoint("dest1"), MclG1Point::MapToPoint("dest2")));
    tx.AddOutput(randomAddress, 500 * COIN, "send");

    auto finalTx = tx.BuildTx();
    BOOST_REQUIRE(finalTx.has_value());

    // Largest-first: the single 1000-COIN input covers 500 + fee, so exactly one
    // input is selected instead of the 20 small ones.
    BOOST_CHECK_EQUAL(finalTx->tx.vin.size(), 1U);

    TxValidationState tx_state;
    BOOST_CHECK(blsct::VerifyTx(CTransaction(finalTx->tx), coins_view_cache, tx_state));
}

BOOST_AUTO_TEST_SUITE_END()
