// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/verification.h>
#include <primitives/transaction.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <wallet/receive.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(blsct_validation_tests)

static CAmount GetFeeValue(const CTransaction& tx)
{
    for (const auto& vout : tx.vout) {
        if (vout.scriptPubKey.IsFee()) return vout.nValue;
    }
    return 0;
}

BOOST_FIXTURE_TEST_CASE(validation_test, TestingSetup)
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
    COutPoint outpoint(txid);

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
    BOOST_CHECK(blsct::VerifyTx(CTransaction(finalTx.value()), coins_view_cache, tx_state));
}

BOOST_FIXTURE_TEST_CASE(validation_reward_test, TestingSetup)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};
    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};

    CMutableTransaction tx;
    TxValidationState tx_state;

    auto out = blsct::CreateOutput(blsct::DoublePublicKey(MclG1Point::Rand(), MclG1Point::Rand()), 900 * COIN, " Reward ");
    tx.vout.push_back(out.out);
    tx.txSig = out.GetSignature();

    BOOST_CHECK(!blsct::VerifyTx(CTransaction(tx), coins_view_cache, tx_state));
    BOOST_CHECK(blsct::VerifyTx(CTransaction(tx), coins_view_cache, tx_state, 900 * COIN));
}

// Verify that a BLSCT input with bit 31 set (reserved for future relative
// timelocks) is rejected with "reserved-sequence-bits" regardless of height/MTP.
BOOST_FIXTURE_TEST_CASE(validation_reserved_sequence_bits_test, TestingSetup)
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
    COutPoint outpoint(txid);

    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    coin.nHeight = 1;
    coin.out = out.out;

    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    auto tx = blsct::TxFactory(blsct_km);
    BOOST_CHECK(tx.AddInput(coins_view_cache, outpoint));
    tx.AddOutput(recvAddress, 900 * COIN, "test");
    auto finalTxOpt = tx.BuildTx();
    BOOST_REQUIRE(finalTxOpt.has_value());

    // Inject reserved bit 31 into the first input's nSequence.
    // 0x80000001 has bit 31 set and is != SEQUENCE_FINAL (0xFFFFFFFF).
    CMutableTransaction mtx(finalTxOpt.value());
    BOOST_REQUIRE(!mtx.vin.empty());
    mtx.vin[0].nSequence = 0x80000001;

    TxValidationState tx_state;
    // Should be rejected with "reserved-sequence-bits" at any height/MTP.
    BOOST_CHECK(!blsct::VerifyTx(CTransaction(mtx), coins_view_cache, tx_state, 0, 0, 1000, 0));
    BOOST_CHECK_EQUAL(tx_state.GetRejectReason(), "reserved-sequence-bits");
}

// Consensus minimum-fee rule: VerifyTx must reject a tx whose fee output
// `nValue` is below GetTransactionWeight(tx) * BLSCT_DEFAULT_FEE.
//
// Lowering the fee on the wire (without changing tx weight) immediately drops
// the actual fee under the per-byte minimum and triggers `blsct-fee-below-min`.
// This is the cheap, local check that catches naive fee-stealing without
// having to inspect the balance equation.
BOOST_FIXTURE_TEST_CASE(validation_min_fee_lowered_fee_rejected_test, TestingSetup)
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
    COutPoint outpoint(txid);

    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    coin.nHeight = 1;
    coin.out = out.out;

    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    auto tx = blsct::TxFactory(blsct_km);
    BOOST_CHECK(tx.AddInput(coins_view_cache, outpoint));
    tx.AddOutput(recvAddress, 900 * COIN, "test");

    auto finalTxOpt = tx.BuildTx();
    BOOST_REQUIRE(finalTxOpt.has_value());

    // Sanity: untampered tx verifies (it was built at exactly the minimum).
    {
        TxValidationState tx_state;
        BOOST_CHECK(blsct::VerifyTx(CTransaction(finalTxOpt.value()), coins_view_cache, tx_state));
    }

    // Lower the fee output's nValue by 1 sat without touching tx weight.
    CMutableTransaction mtx(finalTxOpt.value());
    bool found_fee = false;
    for (auto& vout : mtx.vout) {
        if (vout.scriptPubKey.IsFee()) {
            BOOST_REQUIRE(vout.nValue > 0);
            vout.nValue -= 1;
            found_fee = true;
            break;
        }
    }
    BOOST_REQUIRE(found_fee);

    TxValidationState tx_state;
    BOOST_CHECK(!blsct::VerifyTx(CTransaction(mtx), coins_view_cache, tx_state));
    BOOST_CHECK_EQUAL(tx_state.GetRejectReason(), "blsct-fee-below-min");
}

// Consensus minimum-fee rule defeats the "phantom output" malleability of the
// basic-scheme balance signature.
//
// An attacker who lowers the fee by `delta` and adds a new BLSCT output of
// value `delta` to themselves can in principle keep the BLS aggregate
// consistent (per-output signature for the new output + a balance-sigma patch
// `-gamma_X * H_BLS(BLSCTBALANCE)` they can compute since `BLSCTBALANCE` is a
// public constant and `gamma_X` is their own scalar). But adding a phantom
// output strictly grows GetTransactionWeight(tx), so the per-byte minimum-fee
// check rejects the modified tx with `blsct-fee-below-min` regardless of
// whether the BLS aggregate would otherwise verify.
BOOST_FIXTURE_TEST_CASE(validation_min_fee_phantom_output_rejected_test, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());
    auto attackerAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(1).value());

    const auto txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint(txid);

    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    coin.nHeight = 1;
    coin.out = out.out;

    {
        CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
        coins_view_cache.SetBestBlock(InsecureRand256());
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};
    auto tx = blsct::TxFactory(blsct_km);
    BOOST_CHECK(tx.AddInput(coins_view_cache, outpoint));
    tx.AddOutput(recvAddress, 900 * COIN, "test");

    auto finalTxOpt = tx.BuildTx();
    BOOST_REQUIRE(finalTxOpt.has_value());

    // Build the phantom output the attacker wants to insert.
    constexpr CAmount kStolen = 1;
    auto phantom = blsct::CreateOutput(attackerAddress, kStolen, "stolen");

    // Patch the tx: insert phantom, lower fee by `kStolen`.
    CMutableTransaction mtx(finalTxOpt.value());
    BOOST_REQUIRE(GetFeeValue(CTransaction(finalTxOpt.value())) > kStolen);
    mtx.vout.push_back(phantom.out);

    bool found_fee = false;
    for (auto& vout : mtx.vout) {
        if (vout.scriptPubKey.IsFee()) {
            BOOST_REQUIRE(vout.nValue >= kStolen);
            vout.nValue -= kStolen;
            found_fee = true;
            break;
        }
    }
    BOOST_REQUIRE(found_fee);

    // The attacker doesn't actually need to fix up txSig for the min-fee rule
    // to fire -- the rule runs before the BLS aggregate check, and the phantom
    // output's added bytes alone make `nFee < weight * BLSCT_DEFAULT_FEE`.
    TxValidationState tx_state;
    BOOST_CHECK(!blsct::VerifyTx(CTransaction(mtx), coins_view_cache, tx_state));
    BOOST_CHECK_EQUAL(tx_state.GetRejectReason(), "blsct-fee-below-min");
}

BOOST_AUTO_TEST_SUITE_END()
