#!/usr/bin/env python3
# Copyright (c) 2024 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Simple test for the BLS message signing and verification RPC methods."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class BLSMessageSigningTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Testing BLS message signing and verification")

        # Create a BLSCT wallet
        self.nodes[0].createwallet(wallet_name="test_wallet", blsct=True)
        wallet = self.nodes[0].get_wallet_rpc("test_wallet")

        # Test basic error handling for signblsmessage
        self.test_signblsmessage_errors(wallet)

        # Test basic error handling for verifyblsmessage
        self.test_verifyblsmessage_errors(wallet)

        # Test complete workflow: sign, verify, and verify with wrong message
        self.test_complete_workflow(wallet)

    def test_complete_workflow(self, wallet):
        """Test complete workflow: sign message, verify it, then verify with
        wrong message"""
        self.log.info("Testing complete workflow: sign -> verify -> verify "
                      "with wrong message")

        # Test private key (this is a test key - in real usage users would
        # provide their own)
        test_private_key = (
            "1234567890abcdef1234567890abcdef1234567890abcdef"
            "1234567890abcdef")
        original_message = "Hello, this is the original message!"
        wrong_message = "Hello, this is a different message!"

        # Step 1: Sign the original message
        sign_result = wallet.signblsmessage(test_private_key, original_message)
        self.log.info(f"Signing result: {sign_result}")

        # Verify the result structure
        assert "signature" in sign_result, "Signature not found in result"
        assert "public_key" in sign_result, "Public key not found in result"

        signature = sign_result["signature"]
        public_key = sign_result["public_key"]

        # Verify they are valid hex strings with correct lengths
        assert len(signature) == 192, (
            f"Signature should be 192 hex characters, got {len(signature)}")
        assert len(public_key) == 96, (
            f"Public key should be 96 hex characters, got {len(public_key)}")
        assert all(c in '0123456789abcdef' for c in signature.lower()), (
            "Signature should be valid hex")
        assert all(c in '0123456789abcdef' for c in public_key.lower()), (
            "Public key should be valid hex")

        verify_result = wallet.verifyblsmessage(
            public_key, original_message, signature)
        self.log.info(f"Verification with original message: {verify_result}")

        # Assert that verification result is a boolean
        assert isinstance(verify_result, bool), (
            f"Verification result should be boolean got {type(verify_result)}")
        assert_equal(verify_result, True)

        # Step 3: Verify the signature with a different message (should fail)
        wrong_verify_result = wallet.verifyblsmessage(
            public_key, wrong_message, signature)
        self.log.info(f"Verification with wrong message {wrong_verify_result}")
        assert_equal(wrong_verify_result, False)

    def test_signblsmessage_errors(self, wallet):
        """Test error handling for signblsmessage"""
        self.log.info("Testing signblsmessage error handling")

        # Test with invalid private key length
        invalid_private_key = "1234567890abcdef"  # 16 bytes instead of 32
        assert_raises_rpc_error(
            -8, "Private key must be 32 bytes (64 hex characters)",
            wallet.signblsmessage, invalid_private_key, "test message")

        # Test with invalid hex characters
        invalid_hex_private_key = (
            "1234567890abcdef1234567890abcdef1234567890abcdef"
            "1234567890abcdeg")
        assert_raises_rpc_error(
            -8, "Private key must be 32 bytes (64 hex characters)",
            wallet.signblsmessage, invalid_hex_private_key, "test message")

        # Test with empty private key
        assert_raises_rpc_error(
            -8, "Private key must be 32 bytes (64 hex characters)",
            wallet.signblsmessage, "", "test message")

        # Test with missing parameters
        assert_raises_rpc_error(-1, "signblsmessage", wallet.signblsmessage)

        # Test with only one parameter
        assert_raises_rpc_error(
            -1, "signblsmessage",
            wallet.signblsmessage,
            ("1234567890abcdef1234567890abcdef1234567890abcdef"
             "1234567890abcdef"))

        self.log.info("signblsmessage error handling tests passed")

    def test_verifyblsmessage_errors(self, wallet):
        """Test error handling for verifyblsmessage"""
        self.log.info("Testing verifyblsmessage error handling")

        # Test with invalid public key length
        invalid_public_key = "1234567890abcdef"  # Too short
        test_signature = (
            "1234567890abcdef1234567890abcdef1234567890abcdef"
            "1234567890abcdef1234567890abcdef1234567890abcdef"
            "1234567890abcdef1234567890abcdef1234567890abcdef"
            "1234567890abcdef")
        assert_raises_rpc_error(
            -8, "Public key must be 48 bytes (96 hex characters)",
            wallet.verifyblsmessage, invalid_public_key, "test message",
            test_signature)

        # Test with invalid signature length
        invalid_signature = "1234567890abcdef"  # Too short
        test_public_key = (
            "1234567890abcdef1234567890abcdef1234567890abcdef"
            "1234567890abcdef1234567890abcdef1234567890abcdef")
        assert_raises_rpc_error(
            -8, "Signature must be 96 bytes",
            wallet.verifyblsmessage, test_public_key, "test message",
            invalid_signature)

        # Test with invalid hex characters in public key
        invalid_hex_public_key = (
            "1234567890abcdef1234567890abcdef1234567890abcdef"
            "1234567890abcdef1234567890abcdef1234567890abcdeg")
        assert_raises_rpc_error(
            -8, "Public key must be 48 bytes (96 hex characters)",
            wallet.verifyblsmessage, invalid_hex_public_key, "test message",
            test_signature)

        # Test with missing parameters
        assert_raises_rpc_error(-1, "verifyblsmessage",
                                wallet.verifyblsmessage)

        # Test with only one parameter
        assert_raises_rpc_error(-1, "verifyblsmessage",
                                wallet.verifyblsmessage,
                                test_public_key)

        # Test with only two parameters
        assert_raises_rpc_error(
            -1, "verifyblsmessage",
            wallet.verifyblsmessage, test_public_key, "test message")

        self.log.info("verifyblsmessage error handling tests passed")


if __name__ == '__main__':
    BLSMessageSigningTest().main()
