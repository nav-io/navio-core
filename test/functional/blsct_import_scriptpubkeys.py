#!/usr/bin/env python3
# Copyright (c) 2024 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test BLSCT raw transaction with custom script outputs."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)
import random
from decimal import Decimal

class BLSCTRawTransactionScriptTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True
        self.extra_args = [["-txindex"],["-txindex"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def create_random_script(self):
        """Create a random script for testing"""
        # Create random data (32 bytes)
        random_data = ''.join(random.choices('0123456789abcdef', k=64))
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

        # Test BLSCT raw transaction with custom scripts
        self.test_blsct_raw_transaction_with_script(wallet1, wallet2, address1, address2)
        self.test_blsct_raw_transaction_multiple_scripts(wallet1, wallet2, address1, address2)
        self.test_blsct_raw_transaction_script_verification(wallet1, wallet2, address1, address2)

    def test_blsct_raw_transaction_with_script(self, wallet1, wallet2, address1, address2):
        """Test creating a BLSCT raw transaction with a custom script output"""
        self.log.info("Testing BLSCT raw transaction with custom script")

        # Get unspent outputs from wallet1
        unspent = wallet1.listblsctunspent()
        assert_greater_than(len(unspent), 0)
        utxo = unspent[0]

        # Create a random script
        custom_script = self.create_random_script()
        self.log.info(f"Custom script: {custom_script}")

        # Create transaction inputs
        inputs = [{"txid": utxo['txid']}]

        # Create transaction outputs
        outputs = [
            {"address": address2, "amount": 0.1, "memo": "Regular output"},
            {"address": address2, "script": custom_script, "amount": 0.05, "memo": "Custom script output"}
        ]

        # Create raw transaction
        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)
        self.log.info(f"Created raw transaction: {raw_tx}")

        # Fund the transaction
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)
        self.log.info(f"Funded transaction: {funded_tx}")

        # Sign the transaction
        signed_tx = wallet1.signblsctrawtransaction(funded_tx)
        self.log.info(f"Signed transaction: {signed_tx}")

        # Decode and verify the transaction
        decoded_tx = wallet1.decoderawtransaction(signed_tx)
        self.log.info(f"Decoded transaction: {decoded_tx}")

        # Get BLSCT recovery data to extract amounts and script information
        recovery_data = wallet2.getblsctrecoverydata(signed_tx)
        self.log.info(f"Recovery data: {recovery_data}")

        script_found = False

        for output in recovery_data['outputs']:
            print(f"Output: {output} {output['script']} {custom_script}")
            if 'script' in output and output['script'] == custom_script:
                script_found = True
                assert_equal(output['amount'], Decimal('0.05'))
                self.log.info(f"Found custom script in output: {output}")
                break

        assert_equal(script_found, True)

        # Check that the custom script is in the outputs
        script_found = False
        for output in decoded_tx['vout']:
            if 'scriptPubKey' in output and output['scriptPubKey']['hex'] == custom_script:
                script_found = True
                self.log.info(f"Found custom script in output: {output}")
                break
        assert_equal(script_found, True)

        # Send the transaction
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.log.info(f"Sent transaction {txid}")

        # Generate a block to confirm the transaction
        self.generatetoblsctaddress(self.nodes[0], 1, address1)

        # Verify the transaction is in the mempool and then confirmed
        self.sync_all()

        # Check that wallet2 received the regular output
        balance2 = wallet2.getbalance()
        assert_greater_than(balance2, 0)

        self.log.info("BLSCT raw transaction with custom script test passed")

    def test_blsct_raw_transaction_multiple_scripts(self, wallet1, wallet2, address1, address2):
        """Test creating a BLSCT raw transaction with multiple custom script outputs"""
        self.log.info("Testing BLSCT raw transaction with multiple custom scripts")

        # Get unspent outputs from wallet1
        unspent = wallet1.listblsctunspent()
        assert_greater_than(len(unspent), 0)
        utxo = unspent[0]

        # Create multiple random scripts
        script1 = self.create_random_script()
        script2 = self.create_random_script()
        script3 = self.create_random_script()

        self.log.info(f"Script 1: {script1}")
        self.log.info(f"Script 2: {script2}")
        self.log.info(f"Script 3: {script3}")

        # Create transaction inputs
        inputs = [{"txid": utxo['txid']}]

        # Create transaction outputs with multiple scripts
        outputs = [
            {"address": address2, "script": script1, "amount": 0.02, "memo": "Script 1 output"},
            {"address": address2, "script": script2, "amount": 0.03, "memo": "Script 2 output"},
            {"address": address2, "script": script3, "amount": 0.04, "memo": "Script 3 output"}
        ]

        # Create raw transaction
        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)

        # Fund the transaction
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)

        # Sign the transaction
        signed_tx = wallet1.signblsctrawtransaction(funded_tx)

        # Get BLSCT recovery data to extract amounts and script information
        recovery_data = wallet2.getblsctrecoverydata(signed_tx)
        self.log.info(f"Recovery data: {recovery_data}")

        # Verify the outputs
        assert_equal(len(recovery_data['outputs']), 3)
        # Check that all custom scripts are in the outputs
        scripts_found = set()
        for output in recovery_data['outputs']:
            if 'script' in output and output['gamma'] != "":
                scripts_found.add(output['script'])
        expected_scripts = {script1, script2, script3}
        assert_equal(scripts_found, expected_scripts)

        # Send the transaction
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.log.info(f"Sent transaction {txid} with multiple scripts")

        # Generate a block to confirm the transaction
        self.generatetoblsctaddress(self.nodes[0], 1, address1)

        self.log.info("BLSCT raw transaction with multiple custom scripts test passed")

    def test_blsct_raw_transaction_script_verification(self, wallet1, wallet2, address1, address2):
        """Test that custom scripts in BLSCT transactions can be verified by the node"""
        self.log.info("Testing BLSCT raw transaction script verification")

        # Get unspent outputs from wallet1
        unspent = wallet1.listblsctunspent()
        assert_greater_than(len(unspent), 0)
        utxo = unspent[0]

        # Create a custom script
        custom_script = self.create_random_script()
        self.log.info(f"Custom script: {custom_script}")

        # Create transaction inputs
        inputs = [{"txid": utxo['txid']}]

        # Create transaction outputs with custom script
        outputs = [
            {"address": address2, "amount": 0.05, "memo": "Regular output"},
            {"address": address1, "script": custom_script, "amount": 0.01, "memo": "Custom script output"}
        ]

        # Create raw transaction
        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)

        # Fund the transaction
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)

        # Sign the transaction
        signed_tx = wallet1.signblsctrawtransaction(funded_tx)

        # Send the transaction
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.log.info(f"Sent transaction {txid} with custom script")

        # Generate a block to confirm the transaction
        self.generatetoblsctaddress(self.nodes[0], 1, address1)

        # Wait a moment for the transaction to be processed
        self.sync_all()

        # Also check listunspent for the new outputs
        unspent_after = wallet1.listunspent()
        self.log.info(f"Unspent outputs after transaction: {len(unspent_after)}")

        script_output_found = False

        for utxo in unspent_after:
            self.log.info(f"Unspent output: {utxo}")
            if utxo['scriptPubKey'] == custom_script:
                self.log.info(f"Found custom script in unspent output: {utxo}")
                script_output_found = True
                break

        assert_equal(script_output_found, True)
        # Look for outputs with our custom script using recovery data
        # Use the signed transaction hex directly since the transaction might not be in the wallet
        script_output_found = False
        recovery_data_utxo = wallet1.getblsctrecoverydata(signed_tx)
        for output in recovery_data_utxo['outputs']:
            if 'script' in output and output['script'] == custom_script:
                script_output_found = True
                self.log.info(f"Found custom script in unspent output recovery data: {output}")
                break
        assert_equal(script_output_found, True)

        self.log.info("BLSCT raw transaction script verification test passed")


if __name__ == '__main__':
    BLSCTRawTransactionScriptTest().main()
