// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/rpc.h>
#include <blsct/wallet/verification.h>
#include <key_io.h>
#include <rpc/util.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <algorithm>

#include <boost/test/unit_test.hpp>

using namespace wallet;

BOOST_AUTO_TEST_SUITE(blsct_output_storage_tests)

BOOST_FIXTURE_TEST_CASE(output_storage_basic, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    // Create a BLSCT output
    auto outResult = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    CTxOut txout = outResult.out;

    // Verify output has range proof before adding
    BOOST_CHECK(txout.HasBLSCTRangeProof());
    BOOST_CHECK(txout.HasBLSCTKeys());
    bool isStakedCommitmentBefore = txout.IsStakedCommitment();

    // Save original output hash
    uint256 originalHash = txout.GetHash();

    // Add output to wallet via the public AddToWallet(COutPoint...) method
    COutPoint outpoint(originalHash);
    auto outRef = std::make_shared<const CTxOut>(txout);
    auto* result = wallet->AddToWallet(outpoint, outRef, TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, true);

    BOOST_CHECK(result != nullptr);

    // Find the output in mapOutputs
    BOOST_CHECK(wallet->mapOutputs.contains(outpoint));

    const CWalletOutput& wout = wallet->mapOutputs.at(outpoint);

    // Verify flags are set correctly
    BOOST_CHECK_EQUAL(wout.fBLSCTOutput, true);
    BOOST_CHECK_EQUAL(wout.fStakedCommitment, isStakedCommitmentBefore);

    // Verify range proof is stripped (non-staked output)
    BOOST_CHECK(!wout.out->HasBLSCTRangeProof());

    // Verify BLSCT keys are preserved
    BOOST_CHECK(wout.out->HasBLSCTKeys());

    // Verify the original output hash is preserved
    BOOST_CHECK(wout.outputHash == originalHash);
    BOOST_CHECK(wout.GetOutputHash() == originalHash);

    // Verify recovery data
    BOOST_CHECK(wout.blsctRecoveryData.amount == 1000 * COIN);
}

BOOST_FIXTURE_TEST_CASE(output_storage_serialization_roundtrip, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    auto outResult = blsct::CreateOutput(recvAddress, 500 * COIN, "roundtrip");
    CTxOut txout = outResult.out;
    uint256 originalHash = txout.GetHash();

    // Create a CWalletOutput, set fields, and serialize/deserialize
    auto outRef = std::make_shared<const CTxOut>(txout);
    CWalletOutput wout(outRef, TxStateConfirmed{InsecureRand256(), 1, 0});
    wout.fBLSCTOutput = true;
    wout.fStakedCommitment = false;
    wout.fCoinbase = true;
    wout.outputHash = originalHash;
    wout.blsctRecoveryData.amount = 500 * COIN;

    // Serialize
    DataStream ss{};
    ss << wout;

    // Deserialize
    CWalletOutput wout2(std::make_shared<const CTxOut>(), TxStateInactive{});
    ss >> wout2;

    // Verify all fields survived the round-trip
    BOOST_CHECK_EQUAL(wout2.fBLSCTOutput, true);
    BOOST_CHECK_EQUAL(wout2.fStakedCommitment, false);
    BOOST_CHECK_EQUAL(wout2.fCoinbase, true);
    BOOST_CHECK(wout2.outputHash == originalHash);
    BOOST_CHECK(wout2.blsctRecoveryData.amount == 500 * COIN);
}

BOOST_FIXTURE_TEST_CASE(output_storage_transparent_output, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);

    // Create a transparent (non-BLSCT) output
    CTxOut txout(100 * COIN, CScript() << OP_TRUE);

    auto outRef = std::make_shared<const CTxOut>(txout);
    COutPoint outpoint(txout.GetHash());

    // Add transparent output
    auto* result = wallet->AddToWallet(outpoint, outRef, TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, false);

    BOOST_CHECK(result != nullptr);
    BOOST_CHECK_EQUAL(result->fBLSCTOutput, false);
    BOOST_CHECK_EQUAL(result->fStakedCommitment, false);
    BOOST_CHECK(result->blsctRecoveryData.amount == 100 * COIN);
}

BOOST_FIXTURE_TEST_CASE(output_storage_keeps_range_proof_without_recovery_data, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    auto source_wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    source_wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK2(wallet->cs_wallet, source_wallet->cs_wallet);
    auto source_blsct_km = source_wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(source_blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recv_address = std::get<blsct::DoublePublicKey>(source_blsct_km->GetNewDestination(0).value());
    auto out_result = blsct::CreateOutput(recv_address, 42 * COIN, "watch-only");
    CTxOut txout = out_result.out;
    uint256 original_hash = txout.GetHash();

    COutPoint outpoint(original_hash);
    auto out_ref = std::make_shared<const CTxOut>(txout);
    auto* result = wallet->AddToWallet(outpoint, out_ref, TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, false);

    BOOST_CHECK(result != nullptr);
    BOOST_CHECK(result->fBLSCTOutput);
    BOOST_CHECK(result->out->HasBLSCTRangeProof());
    BOOST_CHECK(result->out->GetHash() == original_hash);
    BOOST_CHECK(result->GetOutputHash() == original_hash);
    BOOST_CHECK_EQUAL(result->blsctRecoveryData.amount, 0);

    // Same output on the wallet that owns the keys: recovery succeeds and amount is cached (range proof can be stripped).
    auto* source_result = source_wallet->AddToWallet(outpoint, out_ref, TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, false);
    BOOST_CHECK(source_result != nullptr);
    BOOST_CHECK(source_result->fBLSCTOutput);
    BOOST_CHECK_EQUAL(source_result->blsctRecoveryData.amount, 42 * COIN);
    BOOST_CHECK(!source_result->out->HasBLSCTRangeProof());
}

BOOST_FIXTURE_TEST_CASE(output_storage_recovers_watchonly_output_with_nonce_hint, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    auto source_wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    source_wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK2(wallet->cs_wallet, source_wallet->cs_wallet);
    auto source_blsct_km = source_wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(source_blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recv_address = std::get<blsct::DoublePublicKey>(source_blsct_km->GetNewDestination(0).value());
    Scalar blinding_key{ParseHex("42c0926471b3bd01ae130d9382c5fca2e2b5000abbf826a93132696ffa5f2c65")};

    BlstG1Point view_key;
    BOOST_CHECK(recv_address.GetViewKey(view_key));
    blsct::PublicKey recovery_nonce(view_key * blinding_key);

    std::vector<unsigned char> hash_bytes(32, 0x11);
    std::vector<unsigned char> spending_key_bytes(blsct::PublicKey::SIZE, 0x22);
    CScript watch_script = blsct::BuildHTLCScript(hash_bytes, spending_key_bytes, spending_key_bytes, 100);

    auto wallet_blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(wallet_blsct_km->AddWatchOnly(watch_script, recovery_nonce));

    auto out_result = blsct::CreateOutput(std::make_pair(recv_address, watch_script), 42 * COIN, "watch-only", TokenId(), blinding_key);
    CTxOut txout = out_result.out;
    uint256 original_hash = txout.GetHash();

    COutPoint outpoint(original_hash);
    auto out_ref = std::make_shared<const CTxOut>(txout);
    auto* result = wallet->AddToWallet(outpoint, out_ref, TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, false);

    BOOST_CHECK(result != nullptr);
    BOOST_CHECK(result->fBLSCTOutput);
    BOOST_CHECK(!result->out->HasBLSCTRangeProof());
    BOOST_CHECK(result->GetOutputHash() == original_hash);
    BOOST_CHECK_EQUAL(result->blsctRecoveryData.amount, 42 * COIN);
    BOOST_CHECK(!result->blsctRecoveryData.gamma.IsZero());
}

BOOST_FIXTURE_TEST_CASE(output_storage_multiple_outputs, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    // Add many outputs, verify they are all correctly stored and stripped
    const int NUM_OUTPUTS = 100;

    for (int i = 0; i < NUM_OUTPUTS; i++) {
        CAmount amount = (i + 1) * COIN;
        auto outResult = blsct::CreateOutput(recvAddress, amount, strprintf("multi%i", i));
        CTxOut txout = outResult.out;
        uint256 originalHash = txout.GetHash();

        COutPoint outpoint(originalHash);
        auto outRef = std::make_shared<const CTxOut>(txout);
        auto* result = wallet->AddToWallet(outpoint, outRef, TxStateConfirmed{InsecureRand256(), i + 1, 0}, nullptr, true, false, TxStateInactive{}, true);

        BOOST_CHECK(result != nullptr);
        BOOST_CHECK_EQUAL(result->fBLSCTOutput, true);
        BOOST_CHECK(!result->out->HasBLSCTRangeProof()); // Stripped
        BOOST_CHECK(result->out->HasBLSCTKeys());         // Keys preserved
        BOOST_CHECK(result->outputHash == originalHash);   // Hash preserved
        BOOST_CHECK(result->blsctRecoveryData.amount == amount);
    }

    BOOST_CHECK_EQUAL(wallet->mapOutputs.size(), NUM_OUTPUTS);
}

BOOST_FIXTURE_TEST_CASE(output_storage_size_savings, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    // Create an output and measure serialized size before and after stripping
    auto outResult = blsct::CreateOutput(recvAddress, 1000 * COIN, "size_test");
    CTxOut txout = outResult.out;

    // Measure original output serialized size
    DataStream ss_original{};
    ss_original << txout;
    size_t originalSize = ss_original.size();

    // Strip the range proof
    CTxOut strippedTxout = txout;
    strippedTxout.blsctData.StripRangeProof();

    DataStream ss_stripped{};
    ss_stripped << strippedTxout;
    size_t strippedSize = ss_stripped.size();

    BOOST_TEST_MESSAGE("Original CTxOut size: " << originalSize << " bytes");
    BOOST_TEST_MESSAGE("Stripped CTxOut size: " << strippedSize << " bytes");
    BOOST_TEST_MESSAGE("Savings: " << (originalSize - strippedSize) << " bytes ("
                       << (100.0 * (originalSize - strippedSize) / originalSize) << "%)");

    // Stripped should be significantly smaller (range proof is ~700+ bytes)
    BOOST_CHECK(strippedSize < originalSize / 2);
    // Keys should still be present
    BOOST_CHECK(strippedTxout.HasBLSCTKeys());
    BOOST_CHECK(!strippedTxout.HasBLSCTRangeProof());
}

BOOST_FIXTURE_TEST_CASE(output_storage_spent_tracking, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    // Add an output
    auto outResult = blsct::CreateOutput(recvAddress, 1000 * COIN, "spent_test");
    CTxOut txout = outResult.out;
    uint256 originalHash = txout.GetHash();
    COutPoint outpoint(originalHash);

    auto outRef = std::make_shared<const CTxOut>(txout);
    auto* result = wallet->AddToWallet(outpoint, outRef, TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, false);

    BOOST_CHECK(result != nullptr);
    BOOST_CHECK(!result->IsSpent());

    // Mark as spent by updating state_spent
    auto* updated = wallet->AddToWallet(outpoint, nullptr, TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateConfirmed{InsecureRand256(), 2, 0}, false);

    BOOST_CHECK(updated != nullptr);
    BOOST_CHECK(updated->IsSpent());
}

// Regression for the "phantom double balance" bug. The staker aggregates a send
// into a block under a different on-chain txid; the wallet's superseded
// pre-aggregation transaction is then evicted as a conflict and re-synced
// Inactive. The per-output spend flag must NOT be reset by that superseded
// transaction (which would un-spend an already-confirmed-spent input, doubling
// the balance), but MUST be reset by a genuine reorg of the actual spending tx.
BOOST_FIXTURE_TEST_CASE(output_storage_spent_sticky_against_superseded_tx, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());
    auto outResult = blsct::CreateOutput(recvAddress, 1000 * COIN, "phantom_test");
    COutPoint outpoint(outResult.out.GetHash());
    auto outRef = std::make_shared<const CTxOut>(outResult.out);

    auto* result = wallet->AddToWallet(outpoint, outRef, TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, false);
    BOOST_REQUIRE(result != nullptr);
    BOOST_CHECK(!result->IsSpent());

    const uint256 aggregate_txid = InsecureRand256();   // on-chain (staker-aggregated) tx
    const uint256 superseded_txid = InsecureRand256();  // wallet's pre-aggregation tx

    // The aggregated transaction confirms: the input is spent by aggregate_txid.
    wallet->AddToWallet(outpoint, nullptr, TxStateConfirmed{InsecureRand256(), 2, 0}, nullptr, true, false, TxStateConfirmed{InsecureRand256(), 2, 0}, false, /*spent_by=*/aggregate_txid);
    BOOST_CHECK(wallet->GetWalletOutput(outpoint)->IsSpent());

    // The superseded pre-aggregation tx is evicted and re-synced Inactive. It is
    // a DIFFERENT txid, so it must not clear the confirmed spend. (Without the
    // fix this resets the flag -> phantom double balance.)
    wallet->AddToWallet(outpoint, nullptr, TxStateInactive{}, nullptr, true, false, TxStateInactive{}, false, /*spent_by=*/superseded_txid);
    BOOST_CHECK_MESSAGE(wallet->GetWalletOutput(outpoint)->IsSpent(),
                        "confirmed spend was cleared by a superseded transaction (phantom double balance)");

    // A genuine reorg of the actual spending tx DOES un-spend the output.
    wallet->AddToWallet(outpoint, nullptr, TxStateInactive{}, nullptr, true, false, TxStateInactive{}, false, /*spent_by=*/aggregate_txid);
    BOOST_CHECK_MESSAGE(!wallet->GetWalletOutput(outpoint)->IsSpent(),
                        "reorg of the actual spending tx should un-spend the output");
}

// Tests for getblsctoutput lookup logic:
// 1. Output-storage mode: stripped output must be found by its original hash.
// 2. Output-storage mode: IsSpent() is correctly reflected.
// 3. Tx-storage mode: output found via mapOutpointHashToWalletTx.

BOOST_FIXTURE_TEST_CASE(getblsctoutput_output_storage_lookup, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    auto outResult = blsct::CreateOutput(recvAddress, 500 * COIN, "output-storage-lookup");
    CTxOut txout = outResult.out;

    // Save original hash *before* stripping.
    uint256 originalHash = txout.GetHash();
    COutPoint outpoint(originalHash);

    auto outRef = std::make_shared<const CTxOut>(txout);
    auto* wout = wallet->AddToWallet(outpoint, outRef, TxStateConfirmed{InsecureRand256(), 1, 0},
                                     nullptr, true, false, TxStateInactive{}, false);
    BOOST_REQUIRE(wout != nullptr);

    // The wallet strips the range proof; GetOutputHash() must still return the original.
    BOOST_CHECK(wout->GetOutputHash() == originalHash);
    BOOST_CHECK(!wout->out->HasBLSCTRangeProof());

    // Lookup by original hash using the same logic as getblsctoutput: the
    // mapOutputs key is the output hash, so this is a direct find().
    const auto found = wallet->mapOutputs.find(COutPoint(originalHash));
    BOOST_REQUIRE(found != wallet->mapOutputs.end());
    BOOST_REQUIRE(found->second.out);
    BOOST_CHECK_EQUAL(found->second.blsctRecoveryData.amount, 500 * COIN);
    BOOST_CHECK(!found->second.IsSpent());
}

BOOST_FIXTURE_TEST_CASE(getblsctoutput_output_storage_spent_flag, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    auto outResult = blsct::CreateOutput(recvAddress, 200 * COIN, "spent-flag");
    CTxOut txout = outResult.out;
    uint256 originalHash = txout.GetHash();
    COutPoint outpoint(originalHash);

    auto outRef = std::make_shared<const CTxOut>(txout);
    wallet->AddToWallet(outpoint, outRef, TxStateConfirmed{InsecureRand256(), 1, 0},
                        nullptr, true, false, TxStateInactive{}, false);

    // Mark spent.
    wallet->AddToWallet(outpoint, nullptr, TxStateConfirmed{InsecureRand256(), 1, 0},
                        nullptr, true, false, TxStateConfirmed{InsecureRand256(), 2, 0}, false);

    // getblsctoutput should report spendable=false for a spent output.
    const auto found = wallet->mapOutputs.find(COutPoint(originalHash));
    BOOST_REQUIRE(found != wallet->mapOutputs.end());
    BOOST_REQUIRE(found->second.out);
    BOOST_CHECK(found->second.IsSpent());
}

// Token outputs must be ingested and credited by the output-storage path just
// like NAV outputs. This is the default wallet mode (createwallet defaults
// storage_output=true for BLSCT wallets). Coverage, not a regression test:
// the token-invisibility bug lived in the gettokenbalance RPC (one-half
// tally), which this test does not reach — blsct_token_output_storage.py is
// the regression test for that.
BOOST_FIXTURE_TEST_CASE(output_storage_token_outputs, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    // GetBlsctBalance walks depth via GetLastBlockHeight; give the wallet a tip.
    wallet->SetLastBlockProcessed(1, InsecureRand256());
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    const auto tokenKey = blsct_km->GetTokenKey(uint256(uint64_t{0x70b}));
    const blsct::PublicKey tokenPublicKey = tokenKey.GetPublicKey();
    const TokenId token_id{tokenPublicKey.GetHash()};

    // A mint output (amount carried in the MintTokenPredicate) and a plain
    // token transfer output (the swap-recv shape).
    auto mintResult = blsct::CreateOutput(recvAddress, 5 * COIN, tokenKey.GetScalar(), tokenKey.GetScalar(), tokenPublicKey, /*transcript_v2=*/true);
    auto transferResult = blsct::CreateOutput(recvAddress, 3 * COIN, "token-transfer", token_id, BlstScalar::Rand(), blsct::NORMAL, 0, /*fAllowZeroValueRangeProof=*/false, /*transcript_v2=*/true);

    for (const auto& [label, res, amount] : {
             std::tuple<const char*, const blsct::UnsignedOutput&, CAmount>{"mint", mintResult, 5 * COIN},
             std::tuple<const char*, const blsct::UnsignedOutput&, CAmount>{"transfer", transferResult, 3 * COIN}}) {
        const CTxOut& txout = res.out;
        BOOST_TEST_CONTEXT(label)
        {
            BOOST_CHECK(txout.HasBLSCTRangeProof());
            BOOST_CHECK(txout.HasBLSCTKeys());
            BOOST_CHECK(txout.tokenId == token_id);

            // Ingestion gate used by AddToWalletIfInvolvingMe's output loop.
            BOOST_CHECK(blsct_km->IsMineMode(txout) != ISMINE_NO);

            const uint256 originalHash = txout.GetHash();
            COutPoint outpoint(originalHash);
            auto outRef = std::make_shared<const CTxOut>(txout);
            auto* result = wallet->AddToWallet(outpoint, outRef, TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, false);
            BOOST_REQUIRE(result != nullptr);
            BOOST_REQUIRE(wallet->mapOutputs.contains(outpoint));

            const CWalletOutput& wout = wallet->mapOutputs.at(outpoint);
            BOOST_CHECK_EQUAL(wout.fBLSCTOutput, true);
            BOOST_CHECK_EQUAL(wout.blsctRecoveryData.amount, amount);

            // The balance path must credit it under its token id and not
            // under NAV.
            BOOST_CHECK_EQUAL(OutputGetCredit(*wallet, wout, ISMINE_SPENDABLE | ISMINE_SPENDABLE_BLSCT, token_id), amount);
            BOOST_CHECK_EQUAL(OutputGetCredit(*wallet, wout, ISMINE_SPENDABLE | ISMINE_SPENDABLE_BLSCT, TokenId()), 0);
        }
    }

    const auto bal = GetBlsctBalance(*wallet, 0, token_id);
    BOOST_CHECK_EQUAL(bal.m_mine_trusted, 8 * COIN);
}

static void CheckBalanceEqual(const Balance& got, const Balance& want)
{
    BOOST_CHECK_EQUAL(got.m_mine_trusted, want.m_mine_trusted);
    BOOST_CHECK_EQUAL(got.m_mine_staked_commitment, want.m_mine_staked_commitment);
    BOOST_CHECK_EQUAL(got.m_mine_pending_staked_commitment, want.m_mine_pending_staked_commitment);
    BOOST_CHECK_EQUAL(got.m_mine_untrusted_pending, want.m_mine_untrusted_pending);
    BOOST_CHECK_EQUAL(got.m_mine_immature, want.m_mine_immature);
    BOOST_CHECK_EQUAL(got.m_watchonly_trusted, want.m_watchonly_trusted);
    BOOST_CHECK_EQUAL(got.m_watchonly_untrusted_pending, want.m_watchonly_untrusted_pending);
    BOOST_CHECK_EQUAL(got.m_watchonly_immature, want.m_watchonly_immature);
}

// getnftbalance tallies a collection in one walk (GetNftBalances,
// GetBlsctNftBalances); each entry must equal the per-NFT GetBalance() and
// GetBlsctBalance() it replaces, and a subid with no entry must hold nothing.
BOOST_FIXTURE_TEST_CASE(nft_balances_match_per_nft_balance, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    wallet->SetLastBlockProcessed(2, InsecureRand256());
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_REQUIRE(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    const uint256 collection{uint256::ONE};
    const uint256 other_collection{uint256(uint64_t{2})};
    const auto output = [&](CAmount amount, const TokenId& token_id) {
        return blsct::CreateOutput(recvAddress, amount, "nft", token_id).out;
    };

    // CWalletTx path. The first tx holds two NFTs of the collection, one of
    // them in two outputs: AddTxBalance() already sums every output of the
    // NFT it is given, so GetNftBalances() must call it once per NFT, not
    // once per output. It also holds an NFT of another collection and NAV.
    // The second tx is confirmed one block later, so min_depth tells them
    // apart.
    CMutableTransaction two_nfts;
    two_nfts.vout.push_back(output(1, TokenId(collection, 1)));
    two_nfts.vout.push_back(output(1, TokenId(collection, 2)));
    two_nfts.vout.push_back(output(1, TokenId(collection, 2)));
    two_nfts.vout.push_back(output(1, TokenId(other_collection, 1)));
    two_nfts.vout.push_back(output(5 * COIN, TokenId()));
    BOOST_REQUIRE(wallet->AddToWallet(MakeTransactionRef(two_nfts), TxStateConfirmed{InsecureRand256(), 1, 0}));
    CMutableTransaction one_nft;
    one_nft.vout.push_back(output(1, TokenId(collection, 3)));
    BOOST_REQUIRE(wallet->AddToWallet(MakeTransactionRef(one_nft), TxStateConfirmed{InsecureRand256(), 2, 0}));

    // mapOutputs path, with no CWalletTx behind the outputs.
    const auto add_output = [&](CAmount amount, const TokenId& token_id, int height) {
        const CTxOut txout{output(amount, token_id)};
        BOOST_REQUIRE(wallet->AddToWallet(COutPoint{txout.GetHash()}, std::make_shared<const CTxOut>(txout),
                                          TxStateConfirmed{InsecureRand256(), height, 0}, nullptr,
                                          /*fFlushOnClose=*/true, /*rescanning_old_block=*/false,
                                          TxStateInactive{}, /*fCoinbase=*/false) != nullptr);
    };
    add_output(1, TokenId(collection, 4), 1);
    add_output(1, TokenId(collection, 5), 2);
    add_output(1, TokenId(other_collection, 4), 1);
    add_output(7 * COIN, TokenId(), 1);

    // Each path credits what it was given, so the comparisons below are not
    // between two zeroes.
    BOOST_REQUIRE_EQUAL(GetBalance(*wallet, 0, false, TokenId(collection, 2)).m_mine_trusted, 2);
    BOOST_REQUIRE_EQUAL(GetBalance(*wallet, 2, false, TokenId(collection, 3)).m_mine_trusted, 0);
    BOOST_REQUIRE_EQUAL(GetBlsctBalance(*wallet, 0, TokenId(collection, 4)).m_mine_trusted, 1);
    BOOST_REQUIRE_EQUAL(GetBlsctBalance(*wallet, 2, TokenId(collection, 5)).m_mine_trusted, 0);

    // Every subid the collection holds, plus one it does not. Subids 1 and 4
    // are also held by the other collection, which must not be credited.
    for (const int min_depth : {0, 1, 2}) {
        for (const bool avoid_reuse : {false, true}) {
            const auto nft_balances{GetNftBalances(*wallet, collection, min_depth, avoid_reuse)};
            const auto blsct_nft_balances{GetBlsctNftBalances(*wallet, collection, min_depth)};
            for (const uint64_t subid : {1, 2, 3, 4, 5, 9}) {
                BOOST_TEST_CONTEXT("min_depth=" << min_depth << " avoid_reuse=" << avoid_reuse << " subid=" << subid)
                {
                    const TokenId token_id{collection, subid};
                    const auto it{nft_balances.find(subid)};
                    CheckBalanceEqual(it == nft_balances.end() ? Balance{} : it->second,
                                      GetBalance(*wallet, min_depth, avoid_reuse, token_id));
                    const auto blsct_it{blsct_nft_balances.find(subid)};
                    CheckBalanceEqual(blsct_it == blsct_nft_balances.end() ? Balance{} : blsct_it->second,
                                      GetBlsctBalance(*wallet, min_depth, token_id));
                }
            }
        }
    }
}

// A transaction is "from me" when it spends an output the wallet knows, even if
// that output does not add to the wallet's NAV debit (here: a token output).
BOOST_FIXTURE_TEST_CASE(is_from_me_token_input, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    CMutableTransaction prev;
    prev.vout.push_back(blsct::CreateOutput(recvAddress, 5 * COIN, "token", TokenId{uint256::ONE}).out);
    BOOST_REQUIRE(wallet->AddToWallet(MakeTransactionRef(prev), TxStateConfirmed{InsecureRand256(), 1, 0}));

    CMutableTransaction spend;
    spend.vin.emplace_back(COutPoint{prev.vout[0].GetHash()});
    const CTransaction spend_tx{spend};

    // The input carries no NAV value, so the old "debit > 0" rule missed it.
    BOOST_CHECK_EQUAL(wallet->GetDebit(spend_tx, ISMINE_ALL), 0);
    BOOST_CHECK(wallet->IsFromMe(spend_tx));

    CMutableTransaction unrelated;
    unrelated.vin.emplace_back(COutPoint{InsecureRand256()});
    BOOST_CHECK(!wallet->IsFromMe(CTransaction{unrelated}));
}

// With output storage the wallet knows its outputs through mapOutputs rather
// than through the transactions that created them.
BOOST_FIXTURE_TEST_CASE(is_from_me_output_storage_input, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    CTxOut txout = blsct::CreateOutput(recvAddress, 5 * COIN, "stored").out;
    COutPoint outpoint{txout.GetHash()};
    BOOST_REQUIRE(wallet->AddToWallet(outpoint, std::make_shared<const CTxOut>(txout), TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, false));
    BOOST_REQUIRE(wallet->GetWalletTxFromOutpoint(outpoint) == nullptr);

    CMutableTransaction spend;
    spend.vin.emplace_back(outpoint);
    BOOST_CHECK(wallet->IsFromMe(CTransaction{spend}));
}

// Regression for issue #470: getwalletinfo reported a staked_commitment_balance
// that still contained a commitment already consumed by a newer stake, so it
// disagreed with liststakedcommitments (which listed only the live one).
//
// A spend reaches the wallet through two independent records: mapTxSpends
// (populated when the spending transaction gets a CWalletTx) and the
// per-output flag in mapOutputs (populated when the spend is observed during
// sync). Either one can be the only witness to a spend. The staked-commitment
// listing has always consulted both; the balance consulted one per path, so a
// commitment recorded as spent in only one of them was excluded from the list
// and still counted in the balance.
BOOST_FIXTURE_TEST_CASE(output_storage_staked_balance_matches_listing, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    wallet->SetLastBlockProcessed(2, InsecureRand256());
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_REQUIRE(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    // Two staked commitments: an old one that a later stake consumed, and the
    // live one that replaced it.
    const CAmount old_amount{31944 * COIN};
    const CAmount live_amount{32088 * COIN};
    const auto add_commitment = [&](CAmount amount, const char* memo, int height) {
        auto res = blsct::CreateOutput(recvAddress, amount, memo, TokenId(), BlstScalar::Rand(),
                                       blsct::STAKED_COMMITMENT, /*minStake=*/amount);
        BOOST_REQUIRE(res.out.IsStakedCommitment());
        COutPoint outpoint(res.out.GetHash());
        auto* wout = wallet->AddToWallet(outpoint, std::make_shared<const CTxOut>(res.out),
                                         TxStateConfirmed{InsecureRand256(), height, 0}, nullptr,
                                         /*fFlushOnClose=*/true, /*rescanning_old_block=*/false,
                                         TxStateInactive{}, /*fCoinbase=*/false);
        BOOST_REQUIRE(wout != nullptr);
        BOOST_REQUIRE_EQUAL(wallet->IsMine(*wout->out), ISMINE_STAKED_COMMITMENT_BLSCT);
        return outpoint;
    };

    const COutPoint old_commitment{add_commitment(old_amount, "old-stake", 1)};
    add_commitment(live_amount, "live-stake", 2);

    BOOST_CHECK_EQUAL(GetBlsctBalance(*wallet).m_mine_staked_commitment, old_amount + live_amount);
    BOOST_CHECK_EQUAL(GetStakedCommitmentInfo(*wallet).size(), 2U);

    // The newer stake consumes the old commitment. Record that spend in
    // mapTxSpends only -- the state a wallet ends up in when the spending
    // transaction is known as a CWalletTx but the per-output flag was never
    // set (or was cleared again, e.g. by a superseded sibling re-sync).
    CMutableTransaction spender;
    spender.vin.emplace_back(old_commitment);
    spender.vout.emplace_back();
    const CWalletTx* spender_wtx = wallet->AddToWallet(MakeTransactionRef(spender),
                                                       TxStateConfirmed{InsecureRand256(), 2, 1});
    BOOST_REQUIRE(spender_wtx != nullptr);
    BOOST_REQUIRE(wallet->IsSpent(old_commitment));
    BOOST_REQUIRE(!wallet->GetWalletOutput(old_commitment)->IsSpent());

    // The listing drops the consumed commitment...
    BOOST_CHECK_EQUAL(GetStakedCommitmentInfo(*wallet).size(), 1U);
    // ...and the balance must agree with it.
    BOOST_CHECK_EQUAL(GetBlsctBalance(*wallet).m_mine_staked_commitment, live_amount);
}

// The mirror image of the case above: the spend is recorded on the output
// (the wallet saw it during sync) but the spending transaction has no
// CWalletTx, so mapTxSpends knows nothing about it. The mapWallet accounting
// pass must not go on crediting the commitment its creating transaction
// produced.
BOOST_FIXTURE_TEST_CASE(output_storage_staked_balance_honours_output_spend_flag, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    wallet->SetLastBlockProcessed(2, InsecureRand256());
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_REQUIRE(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());
    const CAmount amount{31944 * COIN};
    auto res = blsct::CreateOutput(recvAddress, amount, "old-stake", TokenId(), BlstScalar::Rand(),
                                   blsct::STAKED_COMMITMENT, /*minStake=*/amount);
    BOOST_REQUIRE(res.out.IsStakedCommitment());
    const COutPoint outpoint{res.out.GetHash()};

    // The transaction that created the commitment is in mapWallet, and the
    // commitment itself in mapOutputs, as for any locally-created stake.
    CMutableTransaction creator;
    creator.vout.push_back(res.out);
    const CWalletTx* creator_wtx = wallet->AddToWallet(MakeTransactionRef(creator),
                                                       TxStateConfirmed{InsecureRand256(), 1, 0});
    BOOST_REQUIRE(creator_wtx != nullptr);
    BOOST_REQUIRE(wallet->AddToWallet(outpoint, std::make_shared<const CTxOut>(res.out),
                                      TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr,
                                      /*fFlushOnClose=*/true, /*rescanning_old_block=*/false,
                                      TxStateInactive{}, /*fCoinbase=*/false) != nullptr);
    BOOST_CHECK_EQUAL(GetBalance(*wallet).m_mine_staked_commitment, amount);

    // A newer stake consumes it; only the output flag records the spend.
    BOOST_REQUIRE(wallet->AddToWallet(outpoint, nullptr, TxStateConfirmed{InsecureRand256(), 2, 0},
                                      nullptr, /*fFlushOnClose=*/true, /*rescanning_old_block=*/false,
                                      TxStateConfirmed{InsecureRand256(), 2, 0}, /*fCoinbase=*/false,
                                      /*spent_by=*/InsecureRand256()) != nullptr);
    BOOST_REQUIRE(wallet->GetWalletOutput(outpoint)->IsSpent());
    // SyncTransaction() does this for a spend that arrives over the wire; the
    // test drives AddToWallet() directly, so drop the cached credits by hand.
    wallet->MarkDirty();

    BOOST_CHECK_EQUAL(GetStakedCommitmentInfo(*wallet).size(), 0U);
    BOOST_CHECK_EQUAL(GetBalance(*wallet).m_mine_staked_commitment, 0);
    BOOST_CHECK_EQUAL(GetBlsctBalance(*wallet).m_mine_staked_commitment, 0);
}

// Regression for issue #470: re-scanning the block that CREATED an output
// must not un-spend it. The receive side re-adds the output with no spend
// information (an unspent state and a null spender), and treating that as an
// assertion that the output is unspent wiped a spend the chain had already
// confirmed -- so an upgrade rescan brought a consumed staked commitment back
// into staked_commitment_balance permanently.
BOOST_FIXTURE_TEST_CASE(output_storage_rescan_keeps_confirmed_spend, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet = std::make_unique<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_REQUIRE(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());
    auto res = blsct::CreateOutput(recvAddress, 100 * COIN, "rescan-spend");
    const COutPoint outpoint{res.out.GetHash()};
    auto outRef = std::make_shared<const CTxOut>(res.out);
    const TxStateConfirmed created{InsecureRand256(), 1, 0};

    BOOST_REQUIRE(wallet->AddToWallet(outpoint, outRef, created, nullptr, /*fFlushOnClose=*/true,
                                      /*rescanning_old_block=*/false, TxStateInactive{},
                                      /*fCoinbase=*/false) != nullptr);

    // A later transaction spends it, as the vin loop records the spend.
    const uint256 spender{InsecureRand256()};
    BOOST_REQUIRE(wallet->AddToWallet(outpoint, nullptr, TxStateConfirmed{InsecureRand256(), 2, 0}, nullptr,
                                      /*fFlushOnClose=*/true, /*rescanning_old_block=*/false,
                                      TxStateConfirmed{InsecureRand256(), 2, 0}, /*fCoinbase=*/false,
                                      /*spent_by=*/spender) != nullptr);
    BOOST_REQUIRE(wallet->GetWalletOutput(outpoint)->IsSpent());

    // Re-scanning the CREATING block hands the output back with no spend
    // information; the confirmed spend must survive.
    BOOST_REQUIRE(wallet->AddToWallet(outpoint, outRef, created, nullptr, /*fFlushOnClose=*/true,
                                      /*rescanning_old_block=*/true, TxStateInactive{},
                                      /*fCoinbase=*/false) != nullptr);
    BOOST_CHECK_MESSAGE(wallet->GetWalletOutput(outpoint)->IsSpent(),
                        "re-scanning the creating block cleared a confirmed spend");

    // The spending transaction being disconnected still un-spends it.
    BOOST_REQUIRE(wallet->AddToWallet(outpoint, nullptr, TxStateInactive{}, nullptr,
                                      /*fFlushOnClose=*/true, /*rescanning_old_block=*/false,
                                      TxStateInactive{}, /*fCoinbase=*/false,
                                      /*spent_by=*/spender) != nullptr);
    BOOST_CHECK_MESSAGE(!wallet->GetWalletOutput(outpoint)->IsSpent(),
                        "a reorg of the spending tx should un-spend the output");
}

//! A wallet holding one confirmed coin, a cover wallet holding another, and
//! an aggregate in the shape sendtoblsctaddress broadcasts by default: the
//! wallet's own half (coin -> change) combined with a cover half (the cover
//! wallet's coin -> back to the cover wallet, or with `cover_pays_wallet` to
//! the wallet itself).
struct OwnAggregate {
    static constexpr CAmount change_amount{99 * COIN};
    static constexpr CAmount cover_amount{5 * COIN};
    std::shared_ptr<CWallet> wallet;
    std::shared_ptr<CWallet> cover_wallet;
    blsct::DoublePublicKey address;
    COutPoint coin_outpoint;
    COutPoint cover_coin_outpoint;
    COutPoint change_outpoint;
    COutPoint cover_outpoint;
    std::vector<CTxOut> own_half_outputs;
    CTransactionRef aggregate;
};

static OwnAggregate MakeOwnAggregate(interfaces::Chain* chain, bool cover_pays_wallet = false)
{
    OwnAggregate r;
    r.wallet = std::make_shared<CWallet>(chain, "", CreateMockableWalletDatabase());
    r.wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);
    r.cover_wallet = std::make_shared<CWallet>(chain, "", CreateMockableWalletDatabase());
    r.cover_wallet->InitWalletFlags(WALLET_FLAG_BLSCT | WALLET_FLAG_BLSCT_OUTPUT_STORAGE);

    LOCK2(r.wallet->cs_wallet, r.cover_wallet->cs_wallet);
    auto blsct_km = r.wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    auto cover_km = r.cover_wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(cover_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    r.wallet->SetLastBlockProcessed(1, InsecureRand256());
    r.cover_wallet->SetLastBlockProcessed(1, InsecureRand256());

    const auto address = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());
    r.address = address;
    const auto cover_address = std::get<blsct::DoublePublicKey>(cover_km->GetNewDestination(0).value());

    const CTxOut coin = blsct::CreateOutput(address, 100 * COIN, "coin").out;
    r.coin_outpoint = COutPoint(coin.GetHash());
    BOOST_REQUIRE(r.wallet->AddToWallet(r.coin_outpoint, std::make_shared<const CTxOut>(coin), TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, false));
    const CTxOut cover_coin = blsct::CreateOutput(cover_address, 5 * COIN, "cover coin").out;
    r.cover_coin_outpoint = COutPoint(cover_coin.GetHash());
    BOOST_REQUIRE(r.cover_wallet->AddToWallet(r.cover_coin_outpoint, std::make_shared<const CTxOut>(cover_coin), TxStateConfirmed{InsecureRand256(), 1, 0}, nullptr, true, false, TxStateInactive{}, false));

    CMutableTransaction mtx;
    mtx.nVersion |= CTransaction::BLSCT_MARKER;
    mtx.vin.emplace_back(r.coin_outpoint);
    mtx.vin.emplace_back(r.cover_coin_outpoint);
    mtx.vout.push_back(blsct::CreateOutput(address, OwnAggregate::change_amount, "change").out);
    mtx.vout.push_back(blsct::CreateOutput(cover_pays_wallet ? address : cover_address, OwnAggregate::cover_amount, "cover").out);
    r.aggregate = MakeTransactionRef(mtx);
    r.change_outpoint = COutPoint(r.aggregate->vout[0].GetHash());
    r.cover_outpoint = COutPoint(r.aggregate->vout[1].GetHash());
    r.own_half_outputs = {r.aggregate->vout[0]};
    return r;
}

//! The change is the wallet's one coin, trusted and spendable.
static void CheckChangeIsTheSpendableCoin(const OwnAggregate& r) EXCLUSIVE_LOCKS_REQUIRED(r.wallet->cs_wallet)
{
    BOOST_CHECK(r.wallet->IsSpent(r.coin_outpoint));
    BOOST_REQUIRE(r.wallet->GetWalletTx(r.aggregate->GetHash()) != nullptr);
    BOOST_CHECK(CachedTxIsTrusted(*r.wallet, *r.wallet->GetWalletTx(r.aggregate->GetHash())));
    BOOST_CHECK_EQUAL(GetBalance(*r.wallet).m_mine_trusted + GetBlsctBalance(*r.wallet).m_mine_trusted, OwnAggregate::change_amount);
    const auto coins = AvailableBlsctCoins(*r.wallet).All();
    BOOST_REQUIRE_EQUAL(coins.size(), 1U);
    BOOST_CHECK(coins[0].outpoint == r.change_outpoint);
    BOOST_CHECK_EQUAL(coins[0].txout.nValue, OwnAggregate::change_amount);
}

// Regression for issue #479. sendtoblsctaddress merges the wallet's own half
// with cover halves from other wallets and broadcasts the combined tx, whose
// inputs are partly not ours. Learned only from the mempool scan, that tx is
// untrusted (a foreign input) and its change is neither in the trusted balance
// nor spendable, so a chained send fails with "Not enough funds available".
// Recorded by the sender as its own send, the change is trusted and spendable.
BOOST_FIXTURE_TEST_CASE(output_storage_own_aggregate_change_trusted, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    const OwnAggregate r = MakeOwnAggregate(m_node.chain.get());
    LOCK2(r.wallet->cs_wallet, r.cover_wallet->cs_wallet);

    // Seen only through the mempool scan: the coin is spent, the change is
    // ours but untrusted, and nothing is spendable.
    r.wallet->transactionAddedToMempool(r.aggregate);
    BOOST_CHECK(r.wallet->IsSpent(r.coin_outpoint));
    BOOST_REQUIRE(r.wallet->GetWalletTx(r.aggregate->GetHash()) != nullptr);
    BOOST_CHECK(!CachedTxIsTrusted(*r.wallet, *r.wallet->GetWalletTx(r.aggregate->GetHash())));
    BOOST_CHECK_EQUAL(GetBalance(*r.wallet).m_mine_trusted + GetBlsctBalance(*r.wallet).m_mine_trusted, 0);
    BOOST_CHECK_EQUAL(AvailableBlsctCoins(*r.wallet).Size(), 0U);

    // Recorded by the send that built it, the change is trusted and is the
    // one spendable coin.
    BOOST_REQUIRE(r.wallet->RecordBroadcastTransaction(r.aggregate, r.own_half_outputs, {}));
    CheckChangeIsTheSpendableCoin(r);

    // The cover wallet only saw the aggregate spend its coin; it did not
    // build it, so the sender's input still makes its output untrusted.
    r.cover_wallet->transactionAddedToMempool(r.aggregate);
    BOOST_CHECK(r.cover_wallet->IsSpent(r.cover_coin_outpoint));
    BOOST_REQUIRE(r.cover_wallet->GetWalletTx(r.aggregate->GetHash()) != nullptr);
    BOOST_CHECK(!CachedTxIsTrusted(*r.cover_wallet, *r.cover_wallet->GetWalletTx(r.aggregate->GetHash())));
    BOOST_CHECK_EQUAL(GetBalance(*r.cover_wallet).m_mine_trusted + GetBlsctBalance(*r.cover_wallet).m_mine_trusted, 0);
    BOOST_CHECK_EQUAL(AvailableBlsctCoins(*r.cover_wallet).Size(), 0U);
}

// The order a chained send depends on: the send records its aggregate before
// the mempool callback has run, and the change must already be spendable.
// The callback arriving afterwards must leave that state as it is.
BOOST_FIXTURE_TEST_CASE(output_storage_own_aggregate_recorded_before_scan, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    const OwnAggregate r = MakeOwnAggregate(m_node.chain.get());
    LOCK(r.wallet->cs_wallet);

    BOOST_REQUIRE(r.wallet->RecordBroadcastTransaction(r.aggregate, r.own_half_outputs, {}));
    BOOST_CHECK(r.wallet->GetWalletOutput(r.change_outpoint) != nullptr);
    CheckChangeIsTheSpendableCoin(r);

    r.wallet->transactionAddedToMempool(r.aggregate);
    CheckChangeIsTheSpendableCoin(r);
}

// The sync callbacks can confirm the aggregate before the broadcasting RPC
// gets to record it. Recording then must not demote the confirmed spend of
// the wallet's coin back to a mempool spend.
BOOST_FIXTURE_TEST_CASE(output_storage_own_aggregate_recorded_after_confirm, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    const OwnAggregate r = MakeOwnAggregate(m_node.chain.get());
    LOCK(r.wallet->cs_wallet);

    const TxStateConfirmed confirmed{InsecureRand256(), 1, 1};
    BOOST_REQUIRE(r.wallet->AddToWallet(r.aggregate, confirmed));
    BOOST_REQUIRE(r.wallet->AddToWallet(r.coin_outpoint, nullptr, confirmed, nullptr, true, false, confirmed, false, r.aggregate->GetHash()));
    BOOST_REQUIRE(r.wallet->GetWalletOutput(r.coin_outpoint)->state_spent<TxStateConfirmed>());

    BOOST_REQUIRE(r.wallet->RecordBroadcastTransaction(r.aggregate, r.own_half_outputs, {}));
    BOOST_CHECK(r.wallet->GetWalletTx(r.aggregate->GetHash())->isConfirmed());
    BOOST_CHECK(r.wallet->GetWalletTx(r.aggregate->GetHash())->fFromMe);
    BOOST_CHECK(r.wallet->GetWalletOutput(r.coin_outpoint)->state_spent<TxStateConfirmed>());
}

// A cover provider can address its candidate to this wallet. That output is
// funded only by the provider's input, which the aggregate's trust skipped,
// so at depth 0 it must stay untrusted pending -- out of the trusted balance,
// the coin set, and the trust of a tx that spends it -- while the wallet's
// own change stays trusted. Once confirmed, both are trusted.
BOOST_FIXTURE_TEST_CASE(output_storage_own_aggregate_cover_output_untrusted, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    const OwnAggregate r = MakeOwnAggregate(m_node.chain.get(), /*cover_pays_wallet=*/true);
    LOCK(r.wallet->cs_wallet);

    BOOST_REQUIRE(r.wallet->RecordBroadcastTransaction(r.aggregate, r.own_half_outputs, {}));
    const CWalletTx* wtx = r.wallet->GetWalletTx(r.aggregate->GetHash());
    BOOST_REQUIRE(wtx != nullptr);
    BOOST_REQUIRE(r.wallet->GetWalletOutput(r.cover_outpoint) != nullptr);
    BOOST_CHECK(CachedTxIsTrusted(*r.wallet, *wtx));
    BOOST_CHECK(TxTrustCoversOutput(*r.wallet, *wtx, r.change_outpoint.hash));
    BOOST_CHECK(!TxTrustCoversOutput(*r.wallet, *wtx, r.cover_outpoint.hash));
    BOOST_CHECK(IsOutputTrusted(*r.wallet, *r.wallet->GetWalletOutput(r.change_outpoint)));
    BOOST_CHECK(!IsOutputTrusted(*r.wallet, *r.wallet->GetWalletOutput(r.cover_outpoint)));

    const Balance balance{GetBalance(*r.wallet)};
    const Balance blsct_balance{GetBlsctBalance(*r.wallet)};
    BOOST_CHECK_EQUAL(balance.m_mine_trusted + blsct_balance.m_mine_trusted, OwnAggregate::change_amount);
    BOOST_CHECK_EQUAL(balance.m_mine_untrusted_pending + blsct_balance.m_mine_untrusted_pending, OwnAggregate::cover_amount);
    BOOST_CHECK_EQUAL(GetBlsctTrustedBalance(*r.wallet, /*min_depth=*/0).m_mine, OwnAggregate::change_amount);
    const auto coins = AvailableBlsctCoins(*r.wallet).All();
    BOOST_REQUIRE_EQUAL(coins.size(), 1U);
    BOOST_CHECK(coins[0].outpoint == r.change_outpoint);
    const auto mapwallet_coins = AvailableCoins(*r.wallet).All();
    BOOST_CHECK(std::none_of(mapwallet_coins.begin(), mapwallet_coins.end(), [&](const COutput& c) { return c.outpoint == r.cover_outpoint; }));
    CAmount address_balances{0};
    for (const auto& [_, amount] : GetAddressBalances(*r.wallet)) address_balances += amount;
    BOOST_CHECK_EQUAL(address_balances, OwnAggregate::change_amount);

    // A send of this wallet that spends the cover-funded output inherits its
    // missing trust instead of the aggregate's.
    CMutableTransaction child;
    child.nVersion |= CTransaction::BLSCT_MARKER;
    child.vin.emplace_back(r.cover_outpoint);
    const auto address = std::get<blsct::DoublePublicKey>(r.wallet->GetBLSCTKeyMan()->GetNewDestination(0).value());
    child.vout.push_back(blsct::CreateOutput(address, 4 * COIN, "child").out);
    const CWalletTx* child_wtx = r.wallet->AddToWallet(MakeTransactionRef(child), TxStateInMempool{}, [](CWalletTx& w, bool) {
        w.fFromMe = true;
        return true;
    });
    BOOST_REQUIRE(child_wtx != nullptr);
    BOOST_CHECK(!CachedTxIsTrusted(*r.wallet, *child_wtx));

    // Confirmed, the cover's input is settled and its output is trusted too.
    BOOST_REQUIRE(r.wallet->AddToWallet(r.aggregate, TxStateConfirmed{InsecureRand256(), 1, 1}));
    BOOST_CHECK(TxTrustCoversOutput(*r.wallet, *wtx, r.cover_outpoint.hash));
}

// getbalanceforaddress classifies each output of the address itself: the
// change of the aggregate is trusted, the output the cover paid to the same
// address is untrusted pending.
BOOST_FIXTURE_TEST_CASE(output_storage_own_aggregate_cover_output_address_balance, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    const OwnAggregate r = MakeOwnAggregate(m_node.chain.get(), /*cover_pays_wallet=*/true);
    BOOST_REQUIRE(r.wallet->RecordBroadcastTransaction(r.aggregate, r.own_half_outputs, {}));

    WalletContext context;
    context.args = &m_args;
    AddWallet(context, r.wallet);
    JSONRPCRequest request;
    request.context = &context;
    request.params.setArray();
    request.params.push_back(EncodeDestination(CTxDestination{r.address}));
    const UniValue result{getbalanceforaddress().HandleRequest(request)};
    BOOST_CHECK_EQUAL(AmountFromValue(result["mine"]["trusted"]), OwnAggregate::change_amount);
    BOOST_CHECK_EQUAL(AmountFromValue(result["mine"]["untrusted_pending"]), OwnAggregate::cover_amount);
    RemoveWallet(context, r.wallet, /*load_on_start=*/std::nullopt);
}

// The aggregate is already broadcast when the wallet records it, so a wallet
// database error must not fail the send. The mempool sync still adds the tx.
BOOST_FIXTURE_TEST_CASE(output_storage_own_aggregate_record_failure, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    const OwnAggregate r = MakeOwnAggregate(m_node.chain.get());

    GetMockableDatabase(*r.wallet).m_pass = false;
    bool recorded{true};
    BOOST_CHECK_NO_THROW(recorded = r.wallet->RecordBroadcastTransaction(r.aggregate, r.own_half_outputs, {}));
    BOOST_CHECK(!recorded);
    GetMockableDatabase(*r.wallet).m_pass = true;

    LOCK(r.wallet->cs_wallet);
    r.wallet->transactionAddedToMempool(r.aggregate);
    BOOST_CHECK(r.wallet->IsSpent(r.coin_outpoint));
    BOOST_CHECK(r.wallet->GetWalletTx(r.aggregate->GetHash()) != nullptr);
    BOOST_CHECK(r.wallet->GetWalletOutput(r.change_outpoint) != nullptr);
}

// The own half's outputs that the trust covers are part of the wallet record
// and survive a reload.
BOOST_FIXTURE_TEST_CASE(output_storage_own_aggregate_own_half_persists, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    const OwnAggregate r = MakeOwnAggregate(m_node.chain.get(), /*cover_pays_wallet=*/true);
    LOCK(r.wallet->cs_wallet);

    BOOST_REQUIRE(r.wallet->RecordBroadcastTransaction(r.aggregate, r.own_half_outputs, {}));
    const CWalletTx* wtx = r.wallet->GetWalletTx(r.aggregate->GetHash());
    BOOST_REQUIRE(wtx != nullptr);

    DataStream stream;
    stream << *wtx;
    CWalletTx loaded{nullptr, TxStateInactive{}};
    stream >> loaded;
    BOOST_CHECK(loaded.m_own_half_outputs == std::set<uint256>{r.change_outpoint.hash});
    BOOST_CHECK(loaded.mapValue.empty());
}

// An input whose parent wallet tx does not hold the spent output (a stale
// index entry) cannot be vetted. It must make the aggregate untrusted, not
// pass as one of the cover halves' foreign inputs.
BOOST_FIXTURE_TEST_CASE(output_storage_own_aggregate_unlocated_parent_output, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    const OwnAggregate r = MakeOwnAggregate(m_node.chain.get());
    LOCK(r.wallet->cs_wallet);

    BOOST_REQUIRE(r.wallet->RecordBroadcastTransaction(r.aggregate, r.own_half_outputs, {}));
    const CWalletTx* wtx = r.wallet->GetWalletTx(r.aggregate->GetHash());
    BOOST_REQUIRE(wtx != nullptr);
    BOOST_REQUIRE(CachedTxIsTrusted(*r.wallet, *wtx));

    // Point the cover input's outpoint at a wallet tx that does not have it.
    CMutableTransaction other;
    other.nVersion |= CTransaction::BLSCT_MARKER;
    const auto address = std::get<blsct::DoublePublicKey>(r.wallet->GetBLSCTKeyMan()->GetNewDestination(0).value());
    other.vout.push_back(blsct::CreateOutput(address, COIN, "other").out);
    const CWalletTx* other_wtx = r.wallet->AddToWallet(MakeTransactionRef(other), TxStateConfirmed{InsecureRand256(), 1, 2});
    BOOST_REQUIRE(other_wtx != nullptr);
    r.wallet->mapOutpointHashToWalletTx[r.cover_coin_outpoint.hash] = other_wtx;
    BOOST_REQUIRE(r.wallet->GetWalletTxFromOutpoint(r.cover_coin_outpoint) == other_wtx);

    BOOST_CHECK(!CachedTxIsTrusted(*r.wallet, *wtx));
}

BOOST_AUTO_TEST_SUITE_END()
