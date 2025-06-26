#!/usr/bin/env python3
# Copyright (c) 2024 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test the BLSCT raw transaction RPC methods."""

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    assert_greater_than,
)
from test_framework.messages import COIN


class BLSCTRawTransactionTest(BitcoinTestFramework):
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
        block_hashes = self.generatetoblsctaddress(self.nodes[0], 101, address1)

        # Check initial balance
        balance1 = wallet1.getbalance()
        self.log.info(f"Initial balance in wallet1: {balance1}")

        # Test the three RPC methods
        self.test_createblsctrawtransaction(wallet1, wallet2, address1, address2)
        self.test_fundblsctrawtransaction(wallet1, wallet2, address1, address2)
        self.test_signblsctrawtransaction(wallet1, wallet2, address1, address2)
        self.test_decodeblsctrawtransaction(wallet1, wallet2, address1, address2)
        self.test_getblsctrecoverydata(wallet1, wallet2, address1, address2)
        self.test_integration_workflow(wallet1, wallet2, address1, address2)

    def test_createblsctrawtransaction(self, wallet1, wallet2, address1, address2):
        """Test createblsctrawtransaction RPC method"""
        self.log.info("Testing createblsctrawtransaction")

        # Get some unspent outputs
        unspent = wallet1.listblsctunspent()
        assert_greater_than(len(unspent), 0)

        utxo = unspent[0]
        self.log.info(f"Using UTXO: {utxo['txid']}:{utxo['vout']}")

        # Test 1: Create raw transaction with minimal inputs (wallet will fill missing data)
        inputs = [{"txid": utxo['txid'], "vout": utxo['vout']}]
        outputs = [{"address": address2, "amount": 0.1, "memo": "Test transaction"}]

        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)
        self.log.info(f"Created raw transaction: {raw_tx[:100]}...")

        # Test 2: Create raw transaction with all optional fields provided
        inputs_with_data = [{
            "txid": utxo['txid'], 
            "vout": utxo['vout'],
            "value": int(utxo['amount'] * COIN),
            "is_staked_commitment": False
        }]

        raw_tx_with_data = wallet1.createblsctrawtransaction(inputs_with_data, outputs)

        # Test 3: Create raw transaction with multiple outputs
        outputs_multi = [
            {"address": address2, "amount": 0.05, "memo": "First output"},
            {"address": address1, "amount": 0.03, "memo": "Second output"}
        ]

        raw_tx_multi = wallet1.createblsctrawtransaction(inputs, outputs_multi)

        # Test 4: Error cases
        # Invalid address
        outputs_invalid = [{"address": "invalid_address", "amount": 0.1}]
        assert_raises_rpc_error(-5, "Invalid BLSCT address", 
                               wallet1.createblsctrawtransaction, inputs, outputs_invalid)

        # Negative amount
        outputs_negative = [{"address": address2, "amount": -0.1}]
        assert_raises_rpc_error(-3, "Amount out of range", 
                               wallet1.createblsctrawtransaction, inputs, outputs_negative)

        self.log.info("createblsctrawtransaction tests passed")

    def test_fundblsctrawtransaction(self, wallet1, wallet2, address1, address2):
        """Test fundblsctrawtransaction RPC method"""
        self.log.info("Testing fundblsctrawtransaction")

        # Create a raw transaction with insufficient inputs
        inputs = []  # No inputs
        outputs = [{"address": address2, "amount": 0.1, "memo": "Test funding"}]

        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)

        # Fund the transaction
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)
        self.log.info(f"Funded transaction: {funded_tx[:100]}...")

        # Verify the funded transaction is different from the original
        assert funded_tx != raw_tx, "Funded transaction should be different from original"

        # Test with custom change address
        change_address = wallet2.getnewaddress(label="", address_type="blsct")
        funded_tx_with_change = wallet1.fundblsctrawtransaction(raw_tx, change_address)

        # Test error cases
        # Invalid hex string
        assert_raises_rpc_error(-22, "Transaction deserialization faile", 
                               wallet1.fundblsctrawtransaction, "invalid_hex")

        # Invalid change address
        assert_raises_rpc_error(-5, "Invalid BLSCT change address", 
                               wallet1.fundblsctrawtransaction, raw_tx, "invalid_address")

        # Test with insufficient funds (create a transaction larger than available balance)
        balance = wallet1.getbalance()
        large_outputs = [{"address": address2, "amount": balance + 1, "memo": "Too much"}]
        large_raw_tx = wallet1.createblsctrawtransaction(inputs, large_outputs)

        assert_raises_rpc_error(-6, "Insufficient funds", 
                               wallet1.fundblsctrawtransaction, large_raw_tx)

        self.log.info("fundblsctrawtransaction tests passed")

    def test_signblsctrawtransaction(self, wallet1, wallet2, address1, address2):
        """Test signblsctrawtransaction RPC method"""
        self.log.info("Testing signblsctrawtransaction")

        # Create and fund a raw transaction
        inputs = []
        outputs = [{"address": address2, "amount": 0.1, "memo": "Test signing"}]

        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)

        # Sign the transaction
        signed_tx = wallet1.signblsctrawtransaction(funded_tx)
        self.log.info(f"Signed transaction: {signed_tx[:100]}...")

        # Verify the signed transaction is different from the funded transaction
        assert signed_tx != funded_tx, "Signed transaction should be different from funded transaction"

        self.log.info("signblsctrawtransaction tests passed")

    def test_decodeblsctrawtransaction(self, wallet1, wallet2, address1, address2):
        """Test decodeblsctrawtransaction RPC method"""
        self.log.info("Testing decodeblsctrawtransaction")

        # Get some unspent outputs
        unspent = wallet1.listblsctunspent()
        assert_greater_than(len(unspent), 0)

        utxo = unspent[0]
        self.log.info(f"Using UTXO: {utxo['txid']}:{utxo['vout']}")

        # Test 1: Decode a raw transaction
        raw_tx = wallet1.createblsctrawtransaction([{"txid": utxo['txid'], "vout": utxo['vout']}], [])
        decoded_tx = wallet1.decodeblsctrawtransaction(raw_tx)
        self.log.info(f"Decoded transaction: {decoded_tx}")

        # Test 2: Error cases
        # Invalid hex string
        assert_raises_rpc_error(-22, "Transaction deserialization faile", 
                               wallet1.decodeblsctrawtransaction, "invalid_hex")

        self.log.info("decodeblsctrawtransaction tests passed")

    def test_getblsctrecoverydata(self, wallet1, wallet2, address1, address2):
        """Test getblsctrecoverydata RPC method"""
        self.log.info("Testing getblsctrecoverydata")

        # Get some unspent outputs
        unspent = wallet1.listblsctunspent()
        assert_greater_than(len(unspent), 0)

        utxo = unspent[0]
        self.log.info(f"Using UTXO: {utxo['txid']}:{utxo['vout']}")

        # Test 1: Get recovery data for a raw transaction (hex input)
        raw_tx = wallet1.createblsctrawtransaction([{"txid": utxo['txid'], "vout": utxo['vout']}], [])
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)
        signed_tx = wallet1.signblsctrawtransaction(funded_tx)
        recovery_data = wallet1.getblsctrecoverydata(signed_tx)
        self.log.info(f"Recovery data from hex: {recovery_data}")

        assert_equal(len(recovery_data["outputs"]), 2)
        # Verify the structure
        assert "outputs" in recovery_data
        assert isinstance(recovery_data["outputs"], list)
        if len(recovery_data["outputs"]) > 0:
            output = recovery_data["outputs"][0]
            assert "vout" in output
            assert "amount" in output
            assert "gamma" in output
            assert "message" in output

        # Test 2: Get recovery data for a specific vout
        if len(recovery_data["outputs"]) > 0:
            specific_vout = recovery_data["outputs"][0]["vout"]
            recovery_data_specific = wallet1.getblsctrecoverydata(signed_tx, specific_vout)
            self.log.info(f"Recovery data for vout {specific_vout}: {recovery_data_specific}")

            # Should have exactly one output
            assert_equal(len(recovery_data_specific["outputs"]), 1)
            assert_equal(recovery_data_specific["outputs"][0]["vout"], specific_vout)

        # Test 3: Create and broadcast a transaction, then get recovery data by txid
        # Create a simple transaction
        inputs = []
        outputs = [{"address": address2, "amount": 0.01, "memo": "Test recovery data"}]

        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)
        signed_tx = wallet1.signblsctrawtransaction(funded_tx)

        # Broadcast the transaction
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.log.info(f"Broadcasted transaction: {txid}")

        # Mine a block to confirm
        self.generatetoblsctaddress(self.nodes[0], 1, address1)

        # Get the last received transaction to get the actual txid
        transactions = wallet1.listtransactions("*", 1, 0)
        assert_greater_than(len(transactions), 0)
        last_tx = transactions[0]
        actual_txid = last_tx["txid"]
        self.log.info(f"Last received transaction: {actual_txid}")

        # Get recovery data by txid
        recovery_data_txid = wallet1.getblsctrecoverydata(actual_txid)
        recovery_data_signed = wallet1.getblsctrecoverydata(actual_txid)
        self.log.info(f"Recovery data from txid: {recovery_data_txid}")
        self.log.info(f"Recovery data from signed: {recovery_data_signed}")

        assert_equal(recovery_data_txid, recovery_data_signed)

        # Verify we can get recovery data for specific vout
        if len(recovery_data_txid["outputs"]) > 0:
            specific_vout = recovery_data_txid["outputs"][0]["vout"]
            recovery_data_specific_txid = wallet1.getblsctrecoverydata(actual_txid, specific_vout)
            assert_equal(len(recovery_data_specific_txid["outputs"]), 1)

        # Test 4: Error cases
        # Invalid hex string
        assert_raises_rpc_error(-22, "Transaction decode failed", 
                               wallet1.getblsctrecoverydata, "invalid_hex")

        # Invalid vout index
        assert_raises_rpc_error(-8, "vout index out of range", 
                               wallet1.getblsctrecoverydata, signed_tx, 999)

        # Transaction not found in wallet (for txid input)
        fake_txid = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        assert_raises_rpc_error(-8, "Transaction not found in wallet", 
                               wallet1.getblsctrecoverydata, fake_txid)

        self.log.info("getblsctrecoverydata tests passed")

    def test_integration_workflow(self, wallet1, wallet2, address1, address2):
        """Test the complete workflow: create -> fund -> sign -> broadcast"""
        self.log.info("Testing complete BLSCT raw transaction workflow")

        # Step 1: Create raw transaction
        inputs = []
        outputs = [{"address": address2, "amount": 0.05, "memo": "Integration test"}]

        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)
        self.log.info("Step 1: Created raw transaction")

        # Step 2: Fund the transaction
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)
        self.log.info("Step 2: Funded transaction")

        # Step 3: Sign the transaction
        signed_tx = wallet1.signblsctrawtransaction(funded_tx)
        self.log.info("Step 3: Signed transaction")

        initial_balance2 = wallet2.getbalance()
        self.log.info(f"Initial balance in wallet2: {initial_balance2}")

        # Step 4: Broadcast the transaction
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.log.info(f"Step 4: Broadcasted transaction with txid: {txid}")

        # Step 5: Mine a block to confirm the transaction
        block_hashes = self.generatetoblsctaddress(self.nodes[0], 1, address1)
        self.log.info(f"Step 5: Mined block: {block_hashes[0]}")

        # Step 7: Check that the recipient received the funds
        balance2 = wallet2.getbalance()
        self.log.info(f"Final balance in wallet2: {balance2}")
        assert_greater_than(balance2, initial_balance2)

        self.log.info("Complete BLSCT raw transaction workflow test passed")


if __name__ == '__main__':
    BLSCTRawTransactionTest().main() 