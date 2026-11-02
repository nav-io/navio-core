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
    assert_greater_than_or_equal,
)
from test_framework.messages import COIN

# Well-formed regtest BLSCT addresses whose keys are the identity (point at
# infinity). They decode fine and DoublePublicKey::IsValid() accepts them, but
# an output built for them is anyone-can-spend, so every RPC that takes a
# destination must reject them. The one-sided pairs pin both halves of the
# view-key/spend-key check: the encoded payload is the 48-byte compressed
# identity (0xc0 followed by zeroes) and/or the BLS12-381 G1 generator.
NULL_KEY_ADDRESS = "rnv1cqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwvmtas"
NULL_VIEW_KEY_ADDRESS = "rnv1cqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp9l36wnnr97hjsnf2cuvf756cr7rdzxyl9m5hyz6zn368ut3htzcd327s0le0gdwl7e67q9dkgkxhvmdqls40d"
NULL_SPEND_KEY_ADDRESS = "rnv1jlca8fe3jltegf54vwxyl2dvplpk3rz0ja6tjpdpfcar79cm43vxc40g8luh5xh0lva0qzkmytrthsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqma0f57ul"
NULL_KEY_ADDRESSES = (NULL_KEY_ADDRESS, NULL_VIEW_KEY_ADDRESS, NULL_SPEND_KEY_ADDRESS)


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

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=2):
        blocks = []
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            blocks.extend(self.generatetoblsctaddress(node, to_generate, address))
            remaining -= to_generate
        return blocks

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
        self.generate_blsct_blocks(self.nodes[0], address1, 101)

        # Check initial balance
        balance1 = wallet1.getbalance()
        self.log.info(f"Initial balance in wallet1: {balance1}")

        # Test the three RPC methods
        self.test_createblsctrawtransaction(wallet1, wallet2, address1, address2)
        self.test_fundblsctrawtransaction(wallet1, wallet2, address1, address2)
        self.test_signblsctrawtransaction(wallet1, wallet2, address1, address2)
        self.test_decodeblsctrawtransaction(wallet1, wallet2, address1, address2)
        self.test_getblsctrecoverydata(wallet1, wallet2, address1, address2)
        self.test_deriveblsctnonce(wallet1, wallet2, address1, address2)
        self.test_getblsctrecoverydatawithnonce(wallet1, wallet2, address1, address2)
        self.test_integration_workflow(wallet1, wallet2, address1, address2)
        self.test_simulaterawtransaction(wallet1, wallet2, address1, address2)
        # The simulation test restarts node0, so the old wallet1 proxy holds a
        # stale RPC cookie.
        wallet1 = self.nodes[0].get_wallet_rpc("wallet1")
        self.test_nft_output(wallet1, wallet2, address1, address2)

    def _find_output_by_message(self, recovery_data, message):
        for output in recovery_data["outputs"]:
            if output["message"] == message:
                return output
        raise AssertionError(f"No output found with message {message!r}: {recovery_data['outputs']}")

    def test_createblsctrawtransaction(self, wallet1, wallet2, address1, address2):
        """Test createblsctrawtransaction RPC method"""
        self.log.info("Testing createblsctrawtransaction")

        # Get some unspent outputs
        unspent = wallet1.listblsctunspent()
        assert_greater_than(len(unspent), 0)

        utxo = unspent[0]
        # UTXO might not have 'vout' field in the new output hash system
        vout_info = f":{utxo.get('vout', 'N/A')}" if 'vout' in utxo else ""
        self.log.info(f"Using UTXO: {utxo['outid']}{vout_info}")

        # Test 1: Create raw transaction with minimal inputs (wallet will fill missing data)
        inputs = [{"outid": utxo['outid']}]
        outputs = [{"address": address2, "amount": 10000000, "memo": "Test transaction"}]

        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)
        self.log.info(f"Created raw transaction: {raw_tx[:100]}...")

        # Test 2: Create raw transaction with all optional fields provided
        inputs_with_data = [{
            "outid": utxo['outid'],
            "value": int(utxo['amount'] * COIN),
            "is_staked_commitment": False
        }]

        raw_tx_with_data = wallet1.createblsctrawtransaction(inputs_with_data, outputs)
        self.log.info(f"Created raw transaction with data: {raw_tx_with_data[:100]}...")
        # Test 3: Create raw transaction with multiple outputs
        outputs_multi = [
            {"address": address2, "amount": 5000000, "memo": "First output"},
            {"address": address1, "amount": 3000000, "memo": "Second output"}
        ]

        raw_tx_multi = wallet1.createblsctrawtransaction(inputs, outputs_multi)
        self.log.info(f"Created raw transaction with multiple outputs: {raw_tx_multi[:100]}...")
        # Test 4: Error cases
        # Invalid address
        outputs_invalid = [{"address": "invalid_address", "amount": 10000000}]
        assert_raises_rpc_error(-5, "Invalid BLSCT address",
                               wallet1.createblsctrawtransaction, inputs, outputs_invalid)

        # An address encoding the identity for either key decodes fine but is
        # anyone-can-spend, so it must be rejected too.
        for null_address in NULL_KEY_ADDRESSES:
            outputs_null = [{"address": null_address, "amount": 10000000}]
            assert_raises_rpc_error(-5, "BLSCT address has null keys",
                                   wallet1.createblsctrawtransaction, inputs, outputs_null)

        # Negative amount
        outputs_negative = [{"address": address2, "amount": -10000000}]
        assert_raises_rpc_error(-8, "Invalid amount, must be positive",
                               wallet1.createblsctrawtransaction, inputs, outputs_negative)

        self.log.info("createblsctrawtransaction tests passed")

    def test_fundblsctrawtransaction(self, wallet1, wallet2, address1, address2):
        """Test fundblsctrawtransaction RPC method"""
        self.log.info("Testing fundblsctrawtransaction")

        # Create a raw transaction with insufficient inputs
        inputs = []  # No inputs
        outputs = [{"address": address2, "amount": 10000000, "memo": "Test funding"}]

        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)

        # Fund the transaction
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)
        self.log.info(f"Funded transaction: {funded_tx[:100]}...")

        # Verify the funded transaction is different from the original
        assert funded_tx != raw_tx, "Funded transaction should be different from original"

        # Test with custom change address
        change_address = wallet2.getnewaddress(label="", address_type="blsct")
        funded_tx_with_change = wallet1.fundblsctrawtransaction(raw_tx, change_address)
        self.log.info(f"Funded transaction with change: {funded_tx_with_change[:100]}...")

        # Test with a custom absolute fee (above consensus minimum so it is not bumped)
        custom_fee = int(10 * COIN)
        funded_tx_with_fee = wallet1.fundblsctrawtransaction(raw_tx, None, False, custom_fee)
        decoded_funded_tx = wallet1.decodeblsctrawtransaction(funded_tx_with_fee)
        recipient_outputs = [o for o in decoded_funded_tx["outputs"] if o["amount_navoshi"] == 10000000]
        assert_equal(decoded_funded_tx["fee"], custom_fee)
        assert_equal(len(recipient_outputs), 1)
        assert_equal(recipient_outputs[0]["amount_navoshi"], 10000000)

        # Auto fee: consensus weight × fee rate (omit fee; estimate_fee true)
        funded_auto = wallet1.fundblsctrawtransaction(raw_tx, None, False, None, True)
        decoded_auto = wallet1.decodeblsctrawtransaction(funded_auto)
        assert_greater_than(decoded_auto["fee"], 0)
        wallet1.signblsctrawtransaction(funded_auto)  # must be signable

        # Sub-minimum explicit fee is bumped to at least the consensus minimum
        funded_bump = wallet1.fundblsctrawtransaction(raw_tx, None, False, 1)
        decoded_bump = wallet1.decodeblsctrawtransaction(funded_bump)
        assert_greater_than_or_equal(decoded_bump["fee"], 1)
        assert decoded_bump["fee"] > 1, "expect 1 navoshi fee to be raised above strict minimum"

        # Test error cases
        # Invalid hex string
        assert_raises_rpc_error(-22, "Transaction deserialization failed",
                               wallet1.fundblsctrawtransaction, "invalid_hex")

        # Invalid change address
        assert_raises_rpc_error(-5, "Invalid BLSCT address",
                               wallet1.fundblsctrawtransaction, raw_tx, "invalid_address")

        # A change address whose view or spend key is the identity would send
        # the change to an anyone-can-spend output.
        for null_address in NULL_KEY_ADDRESSES:
            assert_raises_rpc_error(-5, "BLSCT address has null keys",
                                   wallet1.fundblsctrawtransaction, raw_tx, null_address)

        # Invalid fee
        assert_raises_rpc_error(-8, "Fee must be a non-negative amount in navoshis",
                               wallet1.fundblsctrawtransaction, raw_tx, None, False, -1)

        # Test with insufficient funds (create a transaction larger than available balance)
        balance = wallet1.getbalance()
        large_outputs = [{"address": address2, "amount": int((balance + 1) * COIN), "memo": "Too much"}]
        large_raw_tx = wallet1.createblsctrawtransaction(inputs, large_outputs)

        assert_raises_rpc_error(-6, "Insufficient funds",
                               wallet1.fundblsctrawtransaction, large_raw_tx)

        self.log.info("fundblsctrawtransaction tests passed")

    def test_signblsctrawtransaction(self, wallet1, wallet2, address1, address2):
        """Test signblsctrawtransaction RPC method"""
        self.log.info("Testing signblsctrawtransaction")

        # Create and fund a raw transaction
        inputs = []
        outputs = [{"address": address2, "amount": 10000000, "memo": "Test signing"}]

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
        vout_info = f":{utxo.get('vout', 'N/A')}" if 'vout' in utxo else ""
        self.log.info(f"Using UTXO: {utxo['outid']}{vout_info}")

        # Test 1: Decode a raw transaction
        input_data = {"outid": utxo['outid']}
        decode_amount_navoshi = 10000000
        raw_tx = wallet1.createblsctrawtransaction(
            [input_data],
            [{"address": address2, "amount": decode_amount_navoshi, "memo": "Decode test"}],
        )
        decoded_tx = wallet1.decodeblsctrawtransaction(raw_tx)
        self.log.info(f"Decoded transaction: {decoded_tx}")
        assert_equal(len(decoded_tx["outputs"]), 1)
        assert_equal(decoded_tx["outputs"][0]["amount"], Decimal("0.10000000"))
        assert_equal(decoded_tx["outputs"][0]["amount_navoshi"], decode_amount_navoshi)

        # Test 2: Error cases
        # Invalid hex string
        assert_raises_rpc_error(-22, "Transaction deserialization failed",
                               wallet1.decodeblsctrawtransaction, "invalid_hex")

        self.log.info("decodeblsctrawtransaction tests passed")

    def test_getblsctrecoverydata(self, wallet1, wallet2, address1, address2):
        """Test getblsctrecoverydata RPC method"""
        self.log.info("Testing getblsctrecoverydata")

        # Get some unspent outputs
        unspent = wallet1.listblsctunspent()
        assert_greater_than(len(unspent), 0)

        utxo = unspent[0]
        self.log.info(f"Using UTXO: {utxo}")

        # Test 1: Get recovery data for a raw transaction (hex input)
        input_data = {"outid": utxo['outid']}
        raw_tx = wallet1.createblsctrawtransaction([input_data], [{"address": address1, "amount": 500000, "memo": "Test script output"}])
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)
        signed_tx = wallet1.signblsctrawtransaction(funded_tx)
        recovery_data = wallet1.getblsctrecoverydata(signed_tx)
        self.log.info(f"Recovery data from hex: {recovery_data}")

        assert_equal(len(recovery_data["outputs"]), 3)
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
        outputs = [{"address": address2, "amount": 1000000, "memo": "Test recovery data"}]

        raw_tx = wallet1.createblsctrawtransaction(inputs, outputs)
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)
        signed_tx = wallet1.signblsctrawtransaction(funded_tx)

        # Broadcast the transaction
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.log.info(f"Broadcasted transaction: {txid}")

        # Mine a block to confirm
        self.generatetoblsctaddress(self.nodes[0], 1, address1)

        # In output-storage mode the wallet does not retain full transaction history,
        # so use the wallet-owned outpoint hash path instead of listtransactions+txid.
        recovery_data_signed = wallet1.getblsctrecoverydata(signed_tx)
        assert_greater_than(len(recovery_data_signed["outputs"]), 0)
        actual_outid = recovery_data_signed["outputs"][0]["out_hash"]
        self.log.info(f"Wallet-owned output hash: {actual_outid}")

        # Get recovery data by outpoint hash
        recovery_data_outid = wallet1.getblsctrecoverydata(actual_outid)
        self.log.info(f"Recovery data from outid: {recovery_data_outid}")
        self.log.info(f"Recovery data from signed tx: {recovery_data_signed}")

        # The outpoint hash input returns the matching output only.
        assert_equal(len(recovery_data_outid["outputs"]), 1)
        assert_equal(recovery_data_outid["outputs"][0], recovery_data_signed["outputs"][0])

        # Verify we can get recovery data for the specific recovered vout
        specific_vout = recovery_data_outid["outputs"][0]["vout"]
        recovery_data_specific_outid = wallet1.getblsctrecoverydata(actual_outid, specific_vout)
        assert_equal(len(recovery_data_specific_outid["outputs"]), 1)
        assert_equal(recovery_data_specific_outid["outputs"][0], recovery_data_outid["outputs"][0])

        # Test 4: Error cases
        # Invalid hex string
        assert_raises_rpc_error(-22, "Transaction decode failed",
                               wallet1.getblsctrecoverydata, "invalid_hex")

        # Invalid vout index
        assert_raises_rpc_error(-8, "vout index out of range",
                               wallet1.getblsctrecoverydata, signed_tx, 999)

        # Transaction or outpoint not found in wallet
        fake_txid = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        assert_raises_rpc_error(-8, "Transaction or outpoint not found in wallet",
                               wallet1.getblsctrecoverydata, fake_txid)

        self.log.info("getblsctrecoverydata tests passed")

    def test_deriveblsctnonce(self, wallet1, wallet2, address1, address2):
        """Test shared-nonce derivation from stored blinding key + destination address."""
        self.log.info("Testing deriveblsctnonce")

        blinding_key_hex = "11" * 32

        nonce1 = wallet1.deriveblsctnonce(blinding_key_hex, address2)
        nonce2 = wallet2.deriveblsctnonce(blinding_key_hex, address2)

        assert_equal(nonce1, nonce2)
        assert_equal(len(nonce1), 96)

        assert_raises_rpc_error(
            -8,
            "Blinding key must be 32 bytes (64 hex characters)",
            wallet1.deriveblsctnonce,
            "abcd",
            address2,
        )
        assert_raises_rpc_error(
            -5,
            "Invalid BLSCT address",
            wallet1.deriveblsctnonce,
            blinding_key_hex,
            "invalid_address",
        )

        self.log.info("deriveblsctnonce tests passed")

    def test_getblsctrecoverydatawithnonce(self, wallet1, wallet2, address1, address2):
        """Test sender-side recovery via stored blinding key + destination address."""
        self.log.info("Testing getblsctrecoverydatawithnonce")

        blinding_key_hex = "22" * 32
        memo = "Test nonce recovery"

        # Create a recipient-addressed output, then derive its shared public nonce
        # from the public destination address and the agreed blinding key.
        raw_tx = wallet1.createblsctrawtransaction([], [{
            "address": address2,
            "amount": 500000,
            "memo": memo,
            "blinding_key": blinding_key_hex,
        }])
        self.log.info(f"Created raw transaction with recipient-derived nonce: {raw_tx[:100]}...")

        # Fund and sign the transaction
        funded_tx = wallet1.fundblsctrawtransaction(raw_tx)
        signed_tx = wallet1.signblsctrawtransaction(funded_tx)

        # The creator can later recover this output using only the stored
        # blinding key and recipient address, without the recipient's keys.
        nonce_hex = wallet1.deriveblsctnonce(blinding_key_hex, address2)

        # Test recovery using the shared public nonce
        recovery_data = wallet1.getblsctrecoverydatawithnonce(signed_tx, nonce_hex)
        self.log.info(f"Recovery data with nonce: {recovery_data}")

        # Compare against the recipient wallet's standard recovery path.
        recipient_recovery = wallet2.getblsctrecoverydata(signed_tx)
        nonce_output = self._find_output_by_message(recovery_data, memo)
        recipient_output = self._find_output_by_message(recipient_recovery, memo)

        assert_equal(nonce_output["amount_navoshi"], recipient_output["amount_navoshi"])
        assert_equal(nonce_output["gamma"], recipient_output["gamma"])
        assert_equal(nonce_output["out_hash"], recipient_output["out_hash"])
        assert_equal(nonce_output["script"], recipient_output["script"])

        # Verify the structure
        assert "txid" in recovery_data
        assert "outputs" in recovery_data
        assert isinstance(recovery_data["outputs"], list)
        assert len(recovery_data["outputs"]) > 0, "No outputs found in recovery data"
        assert any(output["message"] == memo for output in recovery_data["outputs"]), f"No output found with message {memo!r}"

        if len(recovery_data["outputs"]) > 0:
            output = recovery_data["outputs"][0]
            assert "vout" in output
            assert "amount" in output
            assert "gamma" in output
            assert "message" in output

        # Test 2: Get recovery data for a specific vout with nonce
        if len(recovery_data["outputs"]) > 0:
            specific_vout = nonce_output["vout"]
            recovery_data_specific = wallet1.getblsctrecoverydatawithnonce(signed_tx, nonce_hex, specific_vout)
            self.log.info(f"Recovery data for vout {specific_vout} with nonce: {recovery_data_specific}")

            # Should have exactly one output
            assert_equal(len(recovery_data_specific["outputs"]), 1)
            assert_equal(recovery_data_specific["outputs"][0], nonce_output)

        # Test 3: Error cases
        assert_raises_rpc_error(
            -8,
            "Nonce must be 48 bytes (96 hex characters)",
            wallet1.getblsctrecoverydatawithnonce,
            signed_tx,
            "abcd",
        )
        assert_raises_rpc_error(
            -8,
            "Invalid nonce public key",
            wallet1.getblsctrecoverydatawithnonce,
            signed_tx,
            "00" * 48,
        )

        self.log.info("getblsctrecoverydatawithnonce tests passed")

    def test_integration_workflow(self, wallet1, wallet2, address1, address2):
        """Test the complete workflow: create -> fund -> sign -> broadcast"""
        self.log.info("Testing complete BLSCT raw transaction workflow")

        # Step 1: Create raw transaction
        inputs = []
        outputs = [{"address": address2, "amount": 5000000, "memo": "Integration test"}]

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

    def test_simulaterawtransaction(self, wallet1, wallet2, address1, address2):
        """simulaterawtransaction must credit BLSCT outputs by their recovered amount"""
        self.log.info("Testing simulaterawtransaction on a BLSCT transaction")

        amount = Decimal("0.05")
        raw_tx = wallet1.createblsctrawtransaction([], [{"address": address2, "amount": int(amount * COIN), "memo": "Simulate test"}])
        signed_tx = wallet1.signblsctrawtransaction(wallet1.fundblsctrawtransaction(raw_tx))

        # A BLSCT output's nValue is zero, so reading it credits nothing: the
        # recipient would see no change and the sender would lose its change.
        recipient_change = wallet2.simulaterawtransaction([signed_tx])["balance_change"]
        assert_equal(recipient_change, amount)
        self.assert_simulation_matches_broadcast(lambda: signed_tx, wallet1, wallet2)

        # Token and staking transactions come from the wallet's own send RPCs,
        # which commit and broadcast in one go. With -walletbroadcast=0 they
        # stay out of the mempool, so their inputs are still unspent for the
        # simulation and the hex can be broadcast by hand afterwards.
        token_id = wallet1.createtoken({"name": "Simulate"}, 1000)["tokenId"]
        self.generatetoblsctaddress(self.nodes[0], 1, address1)
        wallet1.minttoken(token_id, address1, 1)
        self.generatetoblsctaddress(self.nodes[0], 1, address1)
        self.restart_node(0, extra_args=["-walletbroadcast=0"])
        self.nodes[0].loadwallet("wallet1")
        wallet1 = self.nodes[0].get_wallet_rpc("wallet1")
        self.connect_nodes(0, 1)

        self.log.info("simulaterawtransaction counts a staked commitment as the wallet's own")
        stake_amount = Decimal("200")
        # The stake stays in the wallet, so only the fee leaves it.
        self.assert_simulation_matches_broadcast(lambda: self.unsent_tx_hex(wallet1, lambda: wallet1.stakelock(stake_amount)), wallet1)
        self.generatetoblsctaddress(self.nodes[0], 1, address1)

        self.log.info("simulaterawtransaction debits a spent staked commitment")
        self.assert_simulation_matches_broadcast(lambda: self.unsent_tx_hex(wallet1, lambda: wallet1.stakeunlock(stake_amount / 2)), wallet1)
        self.generatetoblsctaddress(self.nodes[0], 1, address1)

        self.log.info("simulaterawtransaction leaves token outputs out of the NAV change")
        token_tx = self.assert_simulation_matches_broadcast(lambda: self.unsent_tx_hex(wallet1, lambda: wallet1.sendtokentoblsctaddress(token_id, address2, 0.5)), wallet1, wallet2)
        # The recipient gets only tokens, so its NAV balance does not move.
        assert_equal(wallet2.simulaterawtransaction([token_tx])["balance_change"], 0)

        # Later tests expect node0 to broadcast its wallet's sends again.
        self.restart_node(0)
        self.nodes[0].loadwallet("wallet1")
        self.connect_nodes(0, 1)

        self.log.info("simulaterawtransaction tests passed")

    def unsent_tx_hex(self, wallet, send):
        """Run a send RPC on a -walletbroadcast=0 node and return the hex of the transaction it stored"""
        known = {tx["txid"] for tx in wallet.listtransactions("*", 100000, 0, True)}
        send()
        new = {tx["txid"] for tx in wallet.listtransactions("*", 100000, 0, True)} - known
        assert_equal(len(new), 1)
        tx_hex = wallet.gettransaction(new.pop())["hex"]
        assert_raises_rpc_error(-5, None, self.nodes[0].getmempoolentry, self.nodes[0].decoderawtransaction(tx_hex)["txid"])
        return tx_hex

    def nav_total(self, wallet):
        """Every NAV balance bucket a broadcast can move between, staked commitments included"""
        mine = wallet.getbalances()["mine"]
        return sum(mine[bucket] for bucket in ("trusted", "untrusted_pending", "immature", "staked_commitment_balance", "pending_staked_commitment_balance"))

    def assert_simulation_matches_broadcast(self, make_tx, *wallets):
        """Simulate the tx make_tx returns in each wallet, broadcast it and check each NAV balance moved by the simulated change"""
        # Read the balances before make_tx runs: a wallet send RPC marks its
        # inputs spent in the wallet even when it does not broadcast.
        before = [self.nav_total(wallet) for wallet in wallets]
        tx_hex = make_tx()
        simulated = [wallet.simulaterawtransaction([tx_hex])["balance_change"] for wallet in wallets]
        self.nodes[0].sendrawtransaction(tx_hex)
        self.sync_mempools()
        # Each wallet learns of the transaction through its node's validation
        # interface queue, which sendrawtransaction does not wait for.
        for node in self.nodes:
            node.syncwithvalidationinterfacequeue()
        for wallet, change, balance in zip(wallets, simulated, before):
            assert_equal(self.nav_total(wallet) - balance, change)
        return tx_hex

    def test_nft_output(self, wallet1, wallet2, address1, address2):
        """An output's token_id names an NFT as "<collection>#<id>"."""
        self.log.info("Testing a raw transaction sending an NFT")

        collection = wallet1.createnft({"name": "Raw"}, 10)["tokenId"]
        self.generatetoblsctaddress(self.nodes[0], 1, address1)
        nft_outid = wallet1.mintnft(collection, 7, address1, {"id": "seven"})
        self.generatetoblsctaddress(self.nodes[0], 1, address1)
        nft = [{"index": "7", "metadata": [{"key": "id", "value": "seven"}]}]
        assert_equal(wallet1.getnftbalance(collection), nft)

        outputs = [{"address": address2, "amount": 1, "token_id": f"{collection}#7"}]
        assert_raises_rpc_error(-8, "token_id must be a 64-hex token id, followed by #<subid> for an NFT",
                                wallet1.createblsctrawtransaction, [], [{**outputs[0], "token_id": f"{collection}#07"}])

        # The NFT input is named by the outid mintnft returned; funding adds
        # the NAV that pays the fee. An NFT output carries its value in the
        # clear with no range proof, so there is no recovered amount or gamma
        # for the wallet to fill in: pass them.
        nft_input = {"outid": nft_outid, "value": 1, "gamma": "00" * 32}

        def make_nft_tx():
            raw_tx = wallet1.createblsctrawtransaction([nft_input], outputs)
            return wallet1.signblsctrawtransaction(wallet1.fundblsctrawtransaction(raw_tx))

        # The NFT's plaintext value is not NAV: on a full-transaction wallet
        # the sender's NAV moves by the fee alone and the recipient's not at all.
        signed_tx = self.assert_simulation_matches_broadcast(make_nft_tx, wallet1, wallet2)
        assert_equal(wallet2.simulaterawtransaction([signed_tx])["balance_change"], 0)
        self.generatetoblsctaddress(self.nodes[0], 1, address1)
        self.sync_all()

        assert_equal(wallet2.getnftbalance(collection), nft)
        assert_equal(wallet1.getnftbalance(collection), [])

        # The wallet's own record of the send debits the fee and nothing more.
        sent = wallet1.gettransaction(self.nodes[0].decoderawtransaction(signed_tx)["txid"])
        assert_equal(sent["amount"], 0)
        assert_greater_than(0, sent["fee"])


if __name__ == '__main__':
    BLSCTRawTransactionTest(__file__).main()
