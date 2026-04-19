// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/rpc.h>
#include <blsct/wallet/verification.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <wallet/receive.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

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
    BOOST_CHECK(wallet->mapOutputs.count(outpoint) > 0);

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

    MclG1Point view_key;
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
    CAmount expectedTotal = 0;

    for (int i = 0; i < NUM_OUTPUTS; i++) {
        CAmount amount = (i + 1) * COIN;
        auto outResult = blsct::CreateOutput(recvAddress, amount, "multi" + std::to_string(i));
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

        expectedTotal += amount;
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

BOOST_AUTO_TEST_SUITE_END()
