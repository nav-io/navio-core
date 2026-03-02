#!/usr/bin/env python3
# Copyright (c) 2024 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test BLSCT script validation through VerifyTx's VerifyScript + BLS batch
verification pipeline.

Group A: HTLC/atomic_swap outputs (spendingKey nullified, script-only auth)
Group B: Custom script outputs (spendingKey set, dual authentication)
"""

import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_greater_than, assert_raises_rpc_error
from test_framework.messages import COIN


class BLSCTScriptValidationTest(BitcoinTestFramework):
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

        self.nodes[0].createwallet(wallet_name="wallet1", blsct=True)
        self.nodes[1].createwallet(wallet_name="wallet2", blsct=True)

        self.w1 = self.nodes[0].get_wallet_rpc("wallet1")
        self.w2 = self.nodes[1].get_wallet_rpc("wallet2")

        self.addr1 = self.w1.getnewaddress(label="", address_type="blsct")
        self.addr2 = self.w2.getnewaddress(label="", address_type="blsct")

        self.log.info("Generating 101 blocks to fund wallet1")
        self.generatetoblsctaddress(self.nodes[0], 101, self.addr1)

        balance = self.w1.getbalance()
        self.log.info(f"Initial balance in wallet1: {balance}")
        assert_greater_than(balance, 0)

        # Group A: HTLC-based (script-only authentication)
        self.test_wrong_hash_preimage()
        self.test_short_secret()
        self.test_wrong_signing_key()
        self.test_empty_scriptsig_hashlock()

        # Group B: Custom script (dual authentication: script + spendingKey)
        self.test_custom_hash_script_success()
        self.test_custom_hash_script_wrong_preimage()
        self.test_custom_op_true_no_blschecksig()
        self.test_custom_unspendable_op_return()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _create_htlc(self, secret_hash_hex, locktime, blinding_key_hex):
        """Create, fund, sign and broadcast an HTLC. Returns signed tx hex."""
        outputs = [{
            "type": "atomic_swap",
            "address_a": self.addr1,
            "address_b": self.addr2,
            "amount": 1.0,
            "hash": secret_hash_hex,
            "locktime": locktime,
            "blinding_key": blinding_key_hex,
        }]
        raw = self.w1.createblsctrawtransaction([], outputs)
        funded = self.w1.fundblsctrawtransaction(raw)
        signed = self.w1.signblsctrawtransaction(funded)
        self.nodes[0].sendrawtransaction(signed)
        self.generatetoblsctaddress(self.nodes[0], 1, self.addr1)
        return signed

    def _recover_output(self, wallet, signed_tx_hex, expected_sats):
        """Return (out_hash, amount_sats, gamma_hex) for the HTLC output."""
        recovery = wallet.getblsctrecoverydata(signed_tx_hex)
        for out in recovery["outputs"]:
            sats = int(round(out["amount"] * COIN))
            if sats == expected_sats and out.get("gamma"):
                return out["out_hash"], sats, out["gamma"]
        raise AssertionError(
            f"Output with {expected_sats} sats not found: {recovery['outputs']}")

    def _create_custom_script_output(self, script_hex, blinding_key_hex):
        """Create output with a custom scriptPubKey via the 'script' field.
        Returns signed tx hex."""
        outputs = [{
            "address": self.addr1,
            "script": script_hex,
            "amount": 1.0,
            "blinding_key": blinding_key_hex,
        }]
        raw = self.w1.createblsctrawtransaction([], outputs)
        funded = self.w1.fundblsctrawtransaction(raw)
        signed = self.w1.signblsctrawtransaction(funded)
        self.nodes[0].sendrawtransaction(signed)
        self.generatetoblsctaddress(self.nodes[0], 1, self.addr1)
        return signed

    # ------------------------------------------------------------------
    # Group A: HTLC / atomic_swap (spendingKey nullified)
    # ------------------------------------------------------------------
    def test_wrong_hash_preimage(self):
        """Wrong 32-byte secret -> OP_SHA256 produces wrong hash -> fail."""
        self.log.info("=== A1: wrong hash preimage ===")

        secret = bytes(range(32))
        secret_hash = hashlib.sha256(secret).digest()
        bk = "a1" * 32
        locktime = self.nodes[0].getblockcount() + 200

        signed_tx = self._create_htlc(secret_hash.hex(), locktime, bk)
        oh, amt, gamma = self._recover_output(self.w1, signed_tx, COIN)
        sk = self.w1.deriveblsctspendingkey(bk, self.addr1)

        wrong_secret = bytes([0xFF] * 32)
        script_sig = "20" + wrong_secret.hex() + "51"

        inputs = [{"outid": oh, "value": amt, "gamma": gamma,
                   "spending_key": sk, "scriptSig": script_sig}]
        outputs = [{"address": self.addr1, "amount": 0.99}]

        raw = self.w1.createblsctrawtransaction(inputs, outputs)
        funded = self.w1.fundblsctrawtransaction(raw)
        signed = self.w1.signblsctrawtransaction(funded)

        assert_raises_rpc_error(-26, "failed-script-check",
                                self.nodes[0].sendrawtransaction, signed)
        self.log.info("=== A1 PASSED ===")

    def test_short_secret(self):
        """16-byte secret instead of 32 -> OP_SIZE 32 OP_EQUALVERIFY fails."""
        self.log.info("=== A2: short secret ===")

        secret = bytes(range(32))
        secret_hash = hashlib.sha256(secret).digest()
        bk = "a2" * 32
        locktime = self.nodes[0].getblockcount() + 200

        signed_tx = self._create_htlc(secret_hash.hex(), locktime, bk)
        oh, amt, gamma = self._recover_output(self.w1, signed_tx, COIN)
        sk = self.w1.deriveblsctspendingkey(bk, self.addr1)

        short = bytes(range(16))
        script_sig = "10" + short.hex() + "51"

        inputs = [{"outid": oh, "value": amt, "gamma": gamma,
                   "spending_key": sk, "scriptSig": script_sig}]
        outputs = [{"address": self.addr1, "amount": 0.99}]

        raw = self.w1.createblsctrawtransaction(inputs, outputs)
        funded = self.w1.fundblsctrawtransaction(raw)
        signed = self.w1.signblsctrawtransaction(funded)

        assert_raises_rpc_error(-26, "failed-script-check",
                                self.nodes[0].sendrawtransaction, signed)
        self.log.info("=== A2 PASSED ===")

    def test_wrong_signing_key(self):
        """Correct secret but signing key from wrong address -> sig fails."""
        self.log.info("=== A3: wrong signing key ===")

        secret = bytes(range(32))
        secret_hash = hashlib.sha256(secret).digest()
        bk = "a3" * 32
        locktime = self.nodes[0].getblockcount() + 200

        signed_tx = self._create_htlc(secret_hash.hex(), locktime, bk)
        oh, amt, gamma = self._recover_output(self.w1, signed_tx, COIN)

        wrong_sk = self.w2.deriveblsctspendingkey(bk, self.addr2)

        script_sig = "20" + secret.hex() + "51"

        inputs = [{"outid": oh, "value": amt, "gamma": gamma,
                   "spending_key": wrong_sk, "scriptSig": script_sig}]
        outputs = [{"address": self.addr1, "amount": 0.99}]

        raw = self.w1.createblsctrawtransaction(inputs, outputs)
        funded = self.w1.fundblsctrawtransaction(raw)
        signed = self.w1.signblsctrawtransaction(funded)

        assert_raises_rpc_error(-26, "failed-signature-check",
                                self.nodes[0].sendrawtransaction, signed)
        self.log.info("=== A3 PASSED ===")

    def test_empty_scriptsig_hashlock(self):
        """Empty scriptSig on hashlock branch -> script fails (missing data)."""
        self.log.info("=== A4: empty scriptSig ===")

        secret = bytes(range(32))
        secret_hash = hashlib.sha256(secret).digest()
        bk = "a4" * 32
        locktime = self.nodes[0].getblockcount() + 200

        signed_tx = self._create_htlc(secret_hash.hex(), locktime, bk)
        oh, amt, gamma = self._recover_output(self.w1, signed_tx, COIN)
        sk = self.w1.deriveblsctspendingkey(bk, self.addr1)

        inputs = [{"outid": oh, "value": amt, "gamma": gamma,
                   "spending_key": sk, "scriptSig": ""}]
        outputs = [{"address": self.addr1, "amount": 0.99}]

        raw = self.w1.createblsctrawtransaction(inputs, outputs)
        funded = self.w1.fundblsctrawtransaction(raw)
        signed = self.w1.signblsctrawtransaction(funded)

        assert_raises_rpc_error(-26, "failed-script-check",
                                self.nodes[0].sendrawtransaction, signed)
        self.log.info("=== A4 PASSED ===")

    # ------------------------------------------------------------------
    # Group B: Custom script outputs (spendingKey set)
    # ------------------------------------------------------------------
    def test_custom_hash_script_success(self):
        """Custom OP_SHA256 <hash> OP_EQUALVERIFY OP_TRUE script, spend with
        correct preimage + correct spendingKey -> success."""
        self.log.info("=== B1: custom hash script success ===")

        secret = bytes([0xBB] * 32)
        secret_hash = hashlib.sha256(secret).digest()
        bk = "b1" * 32

        # OP_SHA256 OP_PUSH32 <hash> OP_EQUALVERIFY OP_TRUE
        script_hex = "a8" + "20" + secret_hash.hex() + "88" + "51"

        signed_tx = self._create_custom_script_output(script_hex, bk)
        oh, amt, gamma = self._recover_output(self.w1, signed_tx, COIN)
        sk = self.w1.deriveblsctspendingkey(bk, self.addr1)

        # scriptSig: push 32-byte preimage
        ssig = "20" + secret.hex()

        inputs = [{"outid": oh, "value": amt, "gamma": gamma,
                   "spending_key": sk, "scriptSig": ssig}]
        outputs = [{"address": self.addr1, "amount": 0.99}]

        raw = self.w1.createblsctrawtransaction(inputs, outputs)
        funded = self.w1.fundblsctrawtransaction(raw)
        signed = self.w1.signblsctrawtransaction(funded)

        txid = self.nodes[0].sendrawtransaction(signed)
        self.log.info(f"Custom hash script spend accepted: {txid}")
        self.generatetoblsctaddress(self.nodes[0], 1, self.addr1)
        self.log.info("=== B1 PASSED ===")

    def test_custom_hash_script_wrong_preimage(self):
        """Custom SHA256 hash script with wrong preimage -> script check fails."""
        self.log.info("=== B2: custom hash script wrong preimage ===")

        secret = bytes([0xCC] * 32)
        secret_hash = hashlib.sha256(secret).digest()
        bk = "b2" * 32

        script_hex = "a8" + "20" + secret_hash.hex() + "88" + "51"

        signed_tx = self._create_custom_script_output(script_hex, bk)
        oh, amt, gamma = self._recover_output(self.w1, signed_tx, COIN)
        sk = self.w1.deriveblsctspendingkey(bk, self.addr1)

        wrong = bytes([0xDD] * 32)
        ssig = "20" + wrong.hex()

        inputs = [{"outid": oh, "value": amt, "gamma": gamma,
                   "spending_key": sk, "scriptSig": ssig}]
        outputs = [{"address": self.addr1, "amount": 0.99}]

        raw = self.w1.createblsctrawtransaction(inputs, outputs)
        funded = self.w1.fundblsctrawtransaction(raw)
        signed = self.w1.signblsctrawtransaction(funded)

        assert_raises_rpc_error(-26, "failed-script-check",
                                self.nodes[0].sendrawtransaction, signed)
        self.log.info("=== B2 PASSED ===")

    def test_custom_op_true_no_blschecksig(self):
        """OP_TRUE script (trivial, no OP_BLSCHECKSIG).  Script passes but
        the output's spendingKey still requires a valid BLS signature.
        Spending with the correct key must succeed."""
        self.log.info("=== B3: OP_TRUE without OP_BLSCHECKSIG ===")

        bk = "b3" * 32
        script_hex = "51"  # OP_TRUE

        signed_tx = self._create_custom_script_output(script_hex, bk)
        oh, amt, gamma = self._recover_output(self.w1, signed_tx, COIN)
        sk = self.w1.deriveblsctspendingkey(bk, self.addr1)

        inputs = [{"outid": oh, "value": amt, "gamma": gamma,
                   "spending_key": sk, "scriptSig": ""}]
        outputs = [{"address": self.addr1, "amount": 0.99}]

        raw = self.w1.createblsctrawtransaction(inputs, outputs)
        funded = self.w1.fundblsctrawtransaction(raw)
        signed = self.w1.signblsctrawtransaction(funded)

        txid = self.nodes[0].sendrawtransaction(signed)
        self.log.info(f"OP_TRUE spend accepted: {txid}")
        self.generatetoblsctaddress(self.nodes[0], 1, self.addr1)
        self.log.info("=== B3 PASSED ===")

    def test_custom_unspendable_op_return(self):
        """OP_FALSE script is unspendable.  Any attempt to spend
        must fail at script check."""
        self.log.info("=== B4: unspendable OP_FALSE ===")

        bk = "b4" * 32
        script_hex = "00"  # OP_FALSE — leaves false on stack, script fails

        signed_tx = self._create_custom_script_output(script_hex, bk)
        oh, amt, gamma = self._recover_output(self.w1, signed_tx, COIN)
        sk = self.w1.deriveblsctspendingkey(bk, self.addr1)

        inputs = [{"outid": oh, "value": amt, "gamma": gamma,
                   "spending_key": sk, "scriptSig": ""}]
        outputs = [{"address": self.addr1, "amount": 0.99}]

        raw = self.w1.createblsctrawtransaction(inputs, outputs)
        funded = self.w1.fundblsctrawtransaction(raw)
        signed = self.w1.signblsctrawtransaction(funded)

        assert_raises_rpc_error(-26, "failed-script-check",
                                self.nodes[0].sendrawtransaction, signed)
        self.log.info("=== B4 PASSED ===")


if __name__ == '__main__':
    BLSCTScriptValidationTest().main()
