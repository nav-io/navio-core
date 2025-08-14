#!/usr/bin/env python3
# Copyright (c) 2024 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

class NavioBlsctBalanceProofTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        # Set up two nodes for the test
        self.num_nodes = 2
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Creating wallet1 with BLSCT")

        # Create a new wallet
        self.nodes[0].createwallet(wallet_name="wallet1", blsct=True)
        self.nodes[1].createwallet(wallet_name="wallet1", blsct=True)
        wallet = self.nodes[0].get_wallet_rpc("wallet1")
        wallet_2 = self.nodes[1].get_wallet_rpc("wallet1")

        self.log.info("Loading wallet1")

        # Ensure wallet is loaded
        wallets = self.nodes[0].listwallets()
        assert "wallet1" in wallets, "wallet1 was not loaded successfully"

        self.log.info("Generating BLSCT address")

        # Generate a BLSCT address
        blsct_address = wallet.getnewaddress(label="", address_type="blsct")
        blsct_address_2 = wallet_2.getnewaddress(label="", address_type="blsct")

        self.log.info(f"BLSCT address NODE 1: {blsct_address}")
        self.log.info(f"BLSCT address NODE 2: {blsct_address_2}")

        # Generate blocks and fund the BLSCT address
        self.log.info(f"Generating 101 blocks to the BLSCT address {blsct_address}")
        block_hashes = self.generatetoblsctaddress(self.nodes[0], 101, blsct_address)

        self.log.info(f"Generated blocks: {len(block_hashes)}")

        # Check the balance of the wallet
        balance = wallet.getbalance()
        self.log.info(f"Balance in wallet1: {balance}")

        assert_equal(len(block_hashes), 101)
        assert balance > 0, "Balance should be greater than zero after mining"

        # Test creating a balance proof
        self.log.info("Testing createblsctbalanceproof")

        # Create a valid proof
        proof_result = wallet.createblsctbalanceproof(balance / 2)
        assert "proof" in proof_result, "Proof not found in result"
        proof_hex = proof_result["proof"]

        # Test verifying the proof
        self.log.info("Testing verifyblsctbalanceproof")

        # Test with invalid proof format
        assert_raises_rpc_error(-8, "Invalid proof format", wallet.verifyblsctbalanceproof, "invalid")

        # Test with modified proof (corrupt the hex string)
        if len(proof_hex) > 2:
            # Modify the last character of the hex string
            modified_proof = proof_hex[::-1]
            assert_raises_rpc_error(-8, "Invalid proof format",wallet_2.verifyblsctbalanceproof, modified_proof)

        # Verify the valid proof
        verify_result = wallet_2.verifyblsctbalanceproof(proof_hex)
        assert "valid" in verify_result, "Valid field not found in result"
        assert "min_amount" in verify_result, "Min amount field not found in result"
        assert verify_result["valid"], "Proof should be valid"
        assert_equal(verify_result["min_amount"], balance / 2)

if __name__ == '__main__':
    NavioBlsctBalanceProofTest().main()
