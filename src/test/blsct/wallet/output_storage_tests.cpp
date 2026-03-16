// Copyright (c) 2024 The Navio developers
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
