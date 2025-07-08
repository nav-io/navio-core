#!/usr/bin/env python3
# Copyright (c) 2024 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test BLSCT ImportScripts functionality."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    assert_greater_than,
)
import random


class BLSCTImportScriptsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def create_random_script(self):
        """Create a random OP_RETURN script for testing"""
        # Create random data for OP_RETURN
        random_data = ''.join(random.choices('0123456789abcdef', k=32))
        # OP_RETURN followed by data length and data
        script = f"6a20{random_data}"  # 6a = OP_RETURN, 20 = 32 bytes
        return script

    def run_test(self):
        self.log.info("Setting up wallets and generating initial blocks")

        # Create BLSCT wallets
        self.nodes[0].createwallet(wallet_name="wallet1", blsct=True)
        self.nodes[1].createwallet(wallet_name="wallet2", blsct=True)

        wallet1 = self.nodes[0].get_wallet_rpc("wallet1")
        wallet2 = self.nodes[1].get_wallet_rpc("wallet2")

        # Generate BLSCT addresses
        address1 = wallet1.getnewaddress(label="", address_type="blsct")
        address2 = wallet2.getnewaddress(label="", address_type="blsct")

        self.log.info(f"Address 1: {address1}")
        self.log.info(f"Address 2: {address2}")

        # Generate blocks to fund the first wallet
        self.log.info("Generating 101 blocks to fund wallet1")
        self.generatetoblsctaddress(self.nodes[0], 101, address1)

        # Check initial balance
        balance1 = wallet1.getbalance()
        self.log.info(f"Initial balance in wallet1: {balance1}")
        assert_greater_than(balance1, 0)

        # Test the ImportScripts functionality
        self.test_import_scripts_basic(wallet1, wallet2, address1, address2)
        self.test_import_scripts_with_label(wallet1, wallet2, address1, address2)
        self.test_import_scripts_error_cases(wallet1, wallet2, address1, address2)
        self.test_import_scripts_transaction_detection(wallet1, wallet2, address1, address2)

    def test_import_scripts_basic(self, wallet1, wallet2, address1, address2):
        """Test basic ImportScripts functionality"""
        self.log.info("Testing basic ImportScripts functionality")

        # Create random scripts for testing
        script1 = self.create_random_script()
        script2 = self.create_random_script()

        self.log.info(f"Script 1: {script1}")
        self.log.info(f"Script 2: {script2}")

        # Import scripts into wallet2 (watch-only)
        script_pub_keys = [script1, script2]

        # Test importing without label
        result = wallet2.importblsctscript("", script_pub_keys, False, False, 0)
        assert_equal(result, True)

        self.log.info("Basic ImportScripts test passed")

    def test_import_scripts_with_label(self, wallet1, wallet2, address1, address2):
        """Test ImportScripts with label functionality"""
        self.log.info("Testing ImportScripts with label")

        # Create a new wallet for this test
        self.nodes[1].createwallet(wallet_name="wallet3", blsct=True)
        wallet3 = self.nodes[1].get_wallet_rpc("wallet3")

        # Create random script
        script1 = self.create_random_script()

        # Import script with label
        script_pub_keys = [script1]
        label = "test_label"

        result = wallet3.importblsctscript(label, script_pub_keys, False, True, 0)
        assert_equal(result, True)

        self.log.info("ImportScripts with label test passed")

    def test_import_scripts_error_cases(self, wallet1, wallet2, address1, address2):
        """Test ImportScripts error cases"""
        self.log.info("Testing ImportScripts error cases")

        # Create a new wallet for this test
        self.nodes[1].createwallet(wallet_name="wallet4", blsct=True)
        wallet4 = self.nodes[1].get_wallet_rpc("wallet4")

        # Test with invalid script
        invalid_script_pub_keys = ["invalid_script"]

        assert_raises_rpc_error(-8, "Invalid script: not hex",
                               wallet4.importblsctscript, "", invalid_script_pub_keys, False, False, 0)

        # Test with empty scripts array
        empty_script_pub_keys = []

        assert_raises_rpc_error(-8, "No scripts provided",
                               wallet4.importblsctscript, "", empty_script_pub_keys, False, False, 0)

        # Test with non-hex script
        non_hex_script_pub_keys = ["not_hex_script"]

        assert_raises_rpc_error(-8, "Invalid script: not hex",
                               wallet4.importblsctscript, "", non_hex_script_pub_keys, False, False, 0)

        self.log.info("Importscripts error cases test passed")

    def test_import_scripts_transaction_detection(self, wallet1, wallet2, address1, address2):
        """Test that imported scripts detect transactions"""
        self.log.info("Testing Importscripts transaction detection")

        # Create a new wallet for this test
        self.nodes[1].createwallet(wallet_name="wallet5", blsct=True)
        wallet5 = self.nodes[1].get_wallet_rpc("wallet5")

        # Create a random script
        test_script = self.create_random_script()
        self.log.info(f"Test script: {test_script}")

        # Import script into wallet5
        script_pub_keys = [test_script]
        result = wallet5.importblsctscript("", script_pub_keys, False, False, 0)
        assert_equal(result, True)

        # Get some unspent outputs from wallet1
        unspent = wallet1.listblsctunspent()
        assert_greater_than(len(unspent), 0)
        utxo = unspent[0]

        # Create a transaction sending to the imported script using the script parameter
        inputs = [{"txid": utxo['txid'], "vout": utxo['vout']}]
        outputs = [{"address": address1, "amount": 0.05, "memo": "Change output"}]

        # Add output with the imported script
        outputs.append({"script": test_script, "amount": 0.005, "memo": "Test script output", "address": address1})

        # Create and sign the transaction
        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)
        raw_tx = wallet1.fundblsctrawtransaction(raw_tx)
        signed_tx = wallet1.signblsctrawtransaction(raw_tx)

        print(signed_tx)
        print(wallet1.decoderawtransaction(signed_tx))

        # Send the transaction
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.log.info(f"Sent transaction {txid} with script {test_script}")

        # Generate a block to confirm the transaction
        self.generatetoblsctaddress(self.nodes[0], 1, address1)

        # Verify that wallet5 detects the transaction
        # Wait a bit for the wallet to process the transaction
        self.sync_all()

        # Check if the transaction appears in wallet5's transaction list
        transactions = wallet5.listtransactions()
        found_transaction = False
        for tx in transactions:
            print(tx)
            if tx['txid'] == txid:
                found_transaction = True
                assert_equal(tx['category'], 'receive')
                # Note: The amount might be different due to fees, so we just check that it's positive
                assert_greater_than(tx['amount'], 0)
                break

        assert_equal(found_transaction, True, "Imported script should detect incoming transactions")

        # Check balance
        balance = wallet5.getbalance()
        assert_greater_than(balance, 0)

        self.log.info("ImportScripts transaction detection test passed")

if __name__ == '__main__':
    BLSCTImportScriptsTest().main() 