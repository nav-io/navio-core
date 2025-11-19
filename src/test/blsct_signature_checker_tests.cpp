// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/signature.h>
#include <blsct/wallet/verification.h>
#include <coins.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(blsct_signature_checker_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_transaction_signature_checker_bls_signature_storage)
{
    // Create a transaction with one input
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    // Add a transaction input
    CTxIn txin;
    txin.prevout.hash = Txid::FromUint256(uint256::ONE); // Previous transaction hash
    txin.prevout.n = 0;
    txin.nSequence = 0xffffffff;
    tx.vin.push_back(txin);

    // Add a transaction output
    CTxOut txout;
    txout.nValue = 1000000; // 0.01 NAV
    txout.scriptPubKey = CScript() << OP_1;
    tx.vout.push_back(txout);

    // Create the transaction
    CTransaction transaction(tx);

    // Create a TransactionSignatureChecker for the first input
    TransactionSignatureChecker checker(&transaction, 0, 1000000, MissingDataBehavior::FAIL);

    // Create test BLS public keys
    std::vector<unsigned char> pubkey1_data = MclG1Point::Rand().GetVch();
    std::vector<unsigned char> pubkey2_data = MclG1Point::Rand().GetVch();

    // Create scriptSig (unlocking script) - empty for BLS signatures
    CScript scriptSig;

    // Create scriptPubKey (locking script) with multiple OP_BLSCHECKSIG calls
    CScript scriptPubKey;
    scriptPubKey << pubkey1_data << OP_BLSCHECKSIG;
    scriptPubKey << pubkey2_data << OP_BLSCHECKSIG;

    // Execute the script verification
    ScriptError serror;
    uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC;

    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);

    // Should succeed
    BOOST_CHECK(result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);

    // Get the expected input hash (this is what should be stored as the message)
    uint256 expected_input_hash = txin.GetHash();

    // Verify that the key-message pairs were added to the internal vector
    // We need to access the private member, so we'll test this indirectly
    // by checking that the method returns true for valid public keys
    // The actual verification would require access to the private key_message_pairs vector


    // Verify that the input hash is what we expect
    BOOST_CHECK_EQUAL(checker.GetKeyMessagePairs().size(), 2);
    BOOST_CHECK_EQUAL(expected_input_hash, checker.GetKeyMessagePairs()[0].second);
    BOOST_CHECK_EQUAL(expected_input_hash, checker.GetKeyMessagePairs()[1].second);
}

BOOST_AUTO_TEST_CASE(test_transaction_signature_checker_conditional_bls_signature)
{
    // Test with conditional OP_BLSCHECKSIG calls
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    // Add a transaction input
    CTxIn txin;
    txin.prevout.hash = Txid::FromUint256(uint256::ZERO);
    txin.prevout.n = 1;
    txin.nSequence = 0xffffffff;
    tx.vin.push_back(txin);

    // Add a transaction output
    CTxOut txout;
    txout.nValue = 1000000; // 0.01 NAV
    txout.scriptPubKey = CScript() << OP_1;
    tx.vout.push_back(txout);

    // Create the transaction
    CTransaction transaction(tx);

    // Create a TransactionSignatureChecker for the first input
    TransactionSignatureChecker checker(&transaction, 0, 1000000, MissingDataBehavior::FAIL);

    // Create test BLS public keys
    std::vector<unsigned char> pubkey1_data = MclG1Point::Rand().GetVch();
    std::vector<unsigned char> pubkey2_data = MclG1Point::Rand().GetVch();

    // Create scriptSig (unlocking script) - empty for BLS signatures
    CScript scriptSig;

    // Create scriptPubKeys (locking scripts) with conditional OP_BLSCHECKSIG calls
    CScript scriptPubKey1, scriptPubKey2;

    // Script1: true path (first pubkey)
    scriptSig << std::vector<unsigned char>{1};
    scriptPubKey1 << std::vector<unsigned char>{1} << OP_EQUAL;
    scriptPubKey1 << OP_IF << pubkey1_data << OP_BLSCHECKSIG;
    scriptPubKey1 << OP_ELSE << pubkey2_data << OP_BLSCHECKSIG << OP_ENDIF;

    // Script2: false path (second pubkey)
    scriptPubKey2 << std::vector<unsigned char>{2} << OP_EQUAL;
    scriptPubKey2 << OP_IF << pubkey1_data << OP_BLSCHECKSIG;
    scriptPubKey2 << OP_ELSE << pubkey2_data << OP_BLSCHECKSIG << OP_ENDIF;

    // Execute the script verification
    ScriptError serror1, serror2;
    uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC;

    bool result1 = VerifyScript(scriptSig, scriptPubKey1, nullptr, flags, checker, &serror1);
    bool result2 = VerifyScript(scriptSig, scriptPubKey2, nullptr, flags, checker, &serror2);

    // Both should succeed
    BOOST_CHECK(result1);
    BOOST_CHECK(result2);
    BOOST_CHECK_EQUAL(serror1, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(serror2, SCRIPT_ERR_OK);

    // Verify that the key-message pairs were added correctly
    BOOST_CHECK_EQUAL(checker.GetKeyMessagePairs().size(), 2);

    // First execution should use pubkey1
    BOOST_CHECK(checker.GetKeyMessagePairs()[0].first == MclG1Point(pubkey1_data));

    // Second execution should use pubkey2
    BOOST_CHECK(checker.GetKeyMessagePairs()[1].first == MclG1Point(pubkey2_data));
}


BOOST_AUTO_TEST_CASE(test_transaction_signature_checker_single_bls_signature)
{
    // Test with a single OP_BLSCHECKSIG call
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    // Add a transaction input
    CTxIn txin;
    txin.prevout.hash = Txid::FromUint256(uint256::ZERO); // Different previous transaction hash
    txin.prevout.n = 1;
    txin.nSequence = 0xffffffff;
    tx.vin.push_back(txin);

    // Add a transaction output
    CTxOut txout;
    txout.nValue = 5000000; // 0.05 NAV
    txout.scriptPubKey = CScript() << OP_2;
    tx.vout.push_back(txout);

    // Create the transaction
    CTransaction transaction(tx);

    // Create a TransactionSignatureChecker for the first input
    TransactionSignatureChecker checker(&transaction, 0, 5000000, MissingDataBehavior::FAIL);

    // Create a test BLS public key
    std::vector<unsigned char> pubkey_data = MclG1Point::Rand().GetVch();

    // Create scriptSig (unlocking script) - empty for BLS signatures
    CScript scriptSig;

    // Create scriptPubKey (locking script) with OP_BLSCHECKSIG
    CScript scriptPubKey;
    scriptPubKey << pubkey_data << OP_BLSCHECKSIG;

    // Execute the script verification
    ScriptError serror;
    uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC;

    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);

    // Should succeed
    BOOST_CHECK(result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);

    // Get the expected input hash
    uint256 expected_input_hash = txin.GetHash();

    // Verify that the input hash is what we expect
    BOOST_CHECK_EQUAL(checker.GetKeyMessagePairs().size(), 1);
    BOOST_CHECK_EQUAL(expected_input_hash, checker.GetKeyMessagePairs()[0].second);
}

BOOST_AUTO_TEST_CASE(test_transaction_signature_checker_invalid_pubkey)
{
    // Test with invalid public key
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    // Add a transaction input
    CTxIn txin;
    txin.prevout.hash = Txid::FromUint256(uint256::ONE);
    txin.prevout.n = 0;
    txin.nSequence = 0xffffffff;
    tx.vin.push_back(txin);

    // Add a transaction output
    CTxOut txout;
    txout.nValue = 1000000;
    txout.scriptPubKey = CScript() << OP_1;
    tx.vout.push_back(txout);

    // Create the transaction
    CTransaction transaction(tx);

    // Create a TransactionSignatureChecker for the first input
    TransactionSignatureChecker checker(&transaction, 0, 1000000, MissingDataBehavior::FAIL);

    // Create an invalid public key (wrong size)
    std::vector<unsigned char> invalid_pubkey = {0x01, 0x02, 0x03}; // Too short

    // Create scriptSig (unlocking script) - empty for BLS signatures
    CScript scriptSig;

    // Create scriptPubKey (locking script) with OP_BLSCHECKSIG
    CScript scriptPubKey;
    scriptPubKey << invalid_pubkey << OP_BLSCHECKSIG;

    // Execute the script verification
    ScriptError serror;
    uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC;

    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);

    // Should fail with invalid pubkey error
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_PUBKEY);

    // Verify that the key-message pairs were not added to the internal vector
    BOOST_CHECK_EQUAL(checker.GetKeyMessagePairs().size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()