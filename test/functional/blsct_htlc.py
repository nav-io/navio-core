#!/usr/bin/env python3
# Copyright (c) 2024 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test BLSCT HTLC scripts for atomic swaps (hashlock and timelock branches),
plus locktime boundary, timestamp, and edge-case tests.

RPC sequence reference for atomic-swap implementers
===================================================

This file is intended to be the executable reference for constructing and
spending `atomic_swap` outputs with the BLSCT RPCs.

Branch mapping
--------------

- `address_a` is the hashlock branch. Whoever owns this address can spend by
  revealing the 32-byte secret preimage.
- `address_b` is the timelock branch. Whoever owns this address can spend after
  `locktime` via the CLTV branch.
- In a real swap protocol, "redeem" vs "refund" is determined entirely by which
  party you assign to `address_a` and `address_b`.

Funding transaction sequence
----------------------------

1. Agree off-chain on:
   - `address_a`
   - `address_b`
   - `hash = sha256(secret)` as 32-byte hex
   - `locktime` as either a block height (`< 500000000`) or timestamp
     (`>= 500000000`)
   The `blinding_key` does not need to be exchanged off-chain.  The funder
   (party A) knows it because they created the output.  The receiver
   (party B) recovers it from the output's `blsctData.blindingKey` using
   their view private key -- the standard BLSCT output recovery path.
2. Create the HTLC output:

       wallet.createblsctrawtransaction(
           [],
           [{
               "type": "atomic_swap",
               "address_a": address_a,
               "address_b": address_b,
               "amount": amount_btc,
               "hash": secret_hash_hex,
               "locktime": locktime,
               "blinding_key": blinding_key_hex,
           }],
       )

3. Add wallet-selected fee inputs and change with `fundblsctrawtransaction`.
4. Sign it with `signblsctrawtransaction`.
5. Optionally preflight with `testmempoolaccept`.
6. Broadcast with `sendrawtransaction`.

Receiver detection sequence (party B)
--------------------------------------

The receiver does **not** need to receive the raw transaction hex.  After
the initial negotiation (step 1), the receiver imports the expected HTLC
script into their wallet so it is detected automatically during block
scanning:

    receiver_wallet.importblsctscript({
        "type": "atomic_swap",
        "address_a": address_a,
        "address_b": address_b,
        "hash": secret_hash_hex,
        "locktime": locktime,
        "blinding_key": blinding_key_hex,
    })

Once the funder broadcasts and the output is mined, the receiver's wallet
picks it up via the watch-only script match.  The receiver finds the
output by calling `listblsctunspent`, which includes watch-only entries
with `watchonly: true`:

    utxos = receiver_wallet.listblsctunspent()
    htlc_utxos = [u for u in utxos if u.get("watchonly")]

Each entry contains `outid` (the output hash) and `scriptPubKey`.
The receiver then recovers `amount` and `gamma` from the output using
`getblsctrecoverydata`:

    recovery = receiver_wallet.getblsctrecoverydata(utxo["outid"])

Arbitrary (non-HTLC) scripts can also be imported in raw hex form:

    wallet.importblsctscript({"type": "raw", "script": "<hex>"})

Important units
---------------

- HTLC output `amount` is expressed in whole-coin RPC units when creating
  outputs.
- Spend input `value` must be provided in satoshis.
- `getblsctrecoverydata` returns `amount` in whole-coin RPC units, so convert it
  to satoshis before reusing it as an input `value`.

Hashlock spend sequence (`address_a`, redeem/claim path)
--------------------------------------------------------

1. Derive the branch signing key:

       wallet_for_address_a.deriveblsctspendingkey(blinding_key_hex, address_a)

2. Build the hashlock `scriptSig` as:
   - `<push 32-byte secret> <OP_TRUE>`
   - hex form used by this test: `"20" + secret_hex + "51"`
3. Create the spend:

       wallet_for_address_a.createblsctrawtransaction(
           [{
               "outid": out_hash,
               "value": amount_sats,
               "gamma": gamma_hex,
               "spending_key": spending_key_hex,
               "scriptSig": "20" + secret_hex + "51",
           }],
           [{"address": destination, "amount": spend_amount_btc}],
       )

4. Fund it with `fundblsctrawtransaction`.
5. Sign it with `signblsctrawtransaction`.
6. Optionally preflight with `testmempoolaccept`.
7. Broadcast with `sendrawtransaction`.

Timelock spend sequence (`address_b`, refund/timeout path)
----------------------------------------------------------

1. Wait until the lock is actually satisfied:
   - height mode: current chain height must be at least `locktime`
   - timestamp mode: median time past must be at least `locktime`
2. Derive the branch signing key:

       wallet_for_address_b.deriveblsctspendingkey(blinding_key_hex, address_b)

3. Build the timelock `scriptSig` as `<OP_FALSE>`, hex `"00"`.
4. Create the spend, making sure the input `sequence` is set to the same
   absolute lock value used in the script:

       wallet_for_address_b.createblsctrawtransaction(
           [{
               "outid": out_hash,
               "value": amount_sats,
               "gamma": gamma_hex,
               "spending_key": spending_key_hex,
               "scriptSig": "00",
               "sequence": locktime,
           }],
           [{"address": destination, "amount": spend_amount_btc}],
       )

5. Fund it with `fundblsctrawtransaction`.
6. Sign it with `signblsctrawtransaction`.
7. Optionally preflight with `testmempoolaccept`.
8. Broadcast with `sendrawtransaction`.

Common failure cases
--------------------

- Omitting `sequence` on the timelock branch leaves `SEQUENCE_FINAL`
  (`0xFFFFFFFF`), which causes CLTV script validation to fail.
- Setting bit 31 in `sequence` is rejected unless the value is exactly
  `0xFFFFFFFF`.
- Height-mode and timestamp-mode values must match between the script locktime
  and the spend input's `sequence`.
- Broadcasting the HTLC funding transaction before the receiver has verified
  the raw hex (step 5 above) risks the funder committing funds to a script
  the receiver cannot validate.
"""

import hashlib
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_greater_than, assert_raises_rpc_error
from test_framework.messages import COIN

LOCKTIME_THRESHOLD = 500_000_000


class BLSCTHTLCTest(BitcoinTestFramework):
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

        wallet1 = self.nodes[0].get_wallet_rpc("wallet1")
        wallet2 = self.nodes[1].get_wallet_rpc("wallet2")

        address1 = wallet1.getnewaddress(label="", address_type="blsct")
        address2 = wallet2.getnewaddress(label="", address_type="blsct")

        self.log.info("Generating 101 blocks to fund wallet1")
        self.generatetoblsctaddress(self.nodes[0], 101, address1)

        balance1 = wallet1.getbalance()
        self.log.info(f"Initial balance in wallet1: {balance1}")

        self.test_htlc_hashlock(wallet1, wallet2, address1, address2)
        self.test_htlc_timelock(wallet1, wallet2, address1, address2)
        self.test_timelock_exact_boundary(wallet1, wallet2, address1, address2)
        self.test_timelock_too_early(wallet1, wallet2, address1, address2)
        self.test_timelock_timestamp(wallet1, wallet2, address1, address2)
        self.test_timelock_timestamp_too_early(wallet1, wallet2, address1, address2)
        self.test_sequence_final_cltv_fails(wallet1, wallet2, address1, address2)
        self.test_reserved_sequence_bits(wallet1, wallet2, address1, address2)
        self.test_height_time_mode_mismatch(wallet1, wallet2, address1, address2)
        self.test_importblsctscript(wallet1, wallet2, address1, address2)

    def _create_and_broadcast_htlc(self, wallet, miner_addr, address_a, address_b,
                                    amount_btc, secret_hash_hex, locktime, blinding_key_hex):
        """Create, fund, sign and broadcast an HTLC output.
        Returns the signed transaction hex."""
        outputs = [{
            "type": "atomic_swap",
            "address_a": address_a,
            "address_b": address_b,
            "amount": amount_btc,
            "hash": secret_hash_hex,
            "locktime": locktime,
            "blinding_key": blinding_key_hex,
        }]

        raw_tx = wallet.createblsctrawtransaction([], outputs)
        funded_tx = wallet.fundblsctrawtransaction(raw_tx)
        signed_tx = wallet.signblsctrawtransaction(funded_tx)
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.log.info(f"HTLC creation tx broadcast: {txid}")
        self.generatetoblsctaddress(self.nodes[0], 1, miner_addr)
        return signed_tx

    def _recover_htlc_output(self, wallet, signed_tx_hex, expected_amount_sats):
        """Recover the HTLC output from a signed transaction using the wallet's
        standard key derivation. Returns (out_hash, amount_sats, gamma_hex)."""
        recovery = wallet.getblsctrecoverydata(signed_tx_hex)
        for out in recovery["outputs"]:
            recovered_sats = int(round(out["amount"] * COIN))
            if recovered_sats == expected_amount_sats and out.get("gamma"):
                return out["out_hash"], recovered_sats, out["gamma"]
        raise AssertionError(
            f"HTLC output with amount {expected_amount_sats} sats not found in "
            f"recovery data: {recovery['outputs']}")

    def test_htlc_hashlock(self, wallet1, wallet2, address1, address2):
        """Test spending an HTLC output via the hashlock (IF) branch.

        Wallet1 creates an HTLC, then claims it by revealing the secret."""
        self.log.info("=== Testing HTLC hashlock branch ===")

        secret = bytes(range(32))
        secret_hash = hashlib.sha256(secret).digest()
        blinding_key_hex = "01" * 32

        current_height = self.nodes[0].getblockcount()
        htlc_locktime = current_height + 200
        htlc_amount_sats = 1 * COIN
        htlc_amount_btc = 1.0

        self.log.info(f"Secret hash: {secret_hash.hex()}")
        self.log.info(f"HTLC locktime: {htlc_locktime} (current height: {current_height})")

        # Step 1: Create and broadcast the HTLC output
        signed_tx = self._create_and_broadcast_htlc(
            wallet1, address1, address1, address2,
            htlc_amount_btc, secret_hash.hex(), htlc_locktime, blinding_key_hex)

        # Step 2: Recover the HTLC output data (wallet1 can recover since it owns address_a)
        out_hash, amount_sats, gamma_hex = self._recover_htlc_output(
            wallet1, signed_tx, htlc_amount_sats)
        self.log.info(f"HTLC output: hash={out_hash}, amount={amount_sats}, gamma={gamma_hex[:16]}...")

        # Step 3: Derive spending key for address_a (hashlock claimant)
        spending_key = wallet1.deriveblsctspendingkey(blinding_key_hex, address1)
        self.log.info(f"Derived spending key for address_a: {spending_key[:16]}...")

        # Step 4: Build the scriptSig for the IF branch: <push 32-byte secret> <OP_TRUE>
        script_sig = "20" + secret.hex() + "51"

        spend_amount = htlc_amount_btc - 0.01  # minus fee
        spend_inputs = [{
            "outid": out_hash,
            "value": amount_sats,
            "gamma": gamma_hex,
            "spending_key": spending_key,
            "scriptSig": script_sig,
        }]
        spend_outputs = [{"address": address1, "amount": spend_amount}]

        # Step 5: Create, fund, sign and broadcast the spending transaction
        spend_raw = wallet1.createblsctrawtransaction(spend_inputs, spend_outputs)
        spend_funded = wallet1.fundblsctrawtransaction(spend_raw)
        spend_signed = wallet1.signblsctrawtransaction(spend_funded)

        balance_before = wallet1.getbalance()
        spend_txid = self.nodes[0].sendrawtransaction(spend_signed)
        self.log.info(f"Hashlock spend tx broadcast: {spend_txid}")

        self.generatetoblsctaddress(self.nodes[0], 1, address1)

        balance_after = wallet1.getbalance()
        self.log.info(f"Balance before spend: {balance_before}, after: {balance_after}")
        assert_greater_than(balance_after, balance_before - 1)

        self.log.info("=== HTLC hashlock branch test PASSED ===")

    def test_htlc_timelock(self, wallet1, wallet2, address1, address2):
        """Test spending an HTLC output via the timelock (ELSE) branch.

        Wallet1 creates an HTLC. After the locktime expires, wallet2 claims it
        using the timelock branch."""
        self.log.info("=== Testing HTLC timelock branch ===")

        secret = bytes([0xFF] * 32)
        secret_hash = hashlib.sha256(secret).digest()
        blinding_key_hex = "02" * 32

        current_height = self.nodes[0].getblockcount()
        htlc_locktime = current_height + 5
        htlc_amount_sats = 1 * COIN
        htlc_amount_btc = 1.0

        self.log.info(f"HTLC locktime: {htlc_locktime} (current height: {current_height})")

        # Step 1: Create and broadcast the HTLC output
        signed_tx = self._create_and_broadcast_htlc(
            wallet1, address1, address1, address2,
            htlc_amount_btc, secret_hash.hex(), htlc_locktime, blinding_key_hex)

        # Step 2: Recover the HTLC output data. Wallet1 can recover since
        # address_a belongs to it. In a real atomic swap the recovery data
        # (out_hash, value, gamma) would be shared off-chain with wallet2.
        out_hash, amount_sats, gamma_hex = self._recover_htlc_output(
            wallet1, signed_tx, htlc_amount_sats)
        self.log.info(f"HTLC output: hash={out_hash}, amount={amount_sats}")

        # Step 3: Mine blocks until the locktime is reached
        blocks_to_mine = htlc_locktime - self.nodes[0].getblockcount() + 1
        self.log.info(f"Mining {blocks_to_mine} blocks to reach locktime {htlc_locktime}")
        self.generatetoblsctaddress(self.nodes[0], blocks_to_mine, address1)

        current_height = self.nodes[0].getblockcount()
        self.log.info(f"Current height after mining: {current_height}")
        assert_greater_than(current_height, htlc_locktime - 1)

        # Step 4: Derive spending key for address_b (timelock claimant).
        # Wallet2 owns address_b and knows the blinding key (shared off-chain).
        spending_key = wallet2.deriveblsctspendingkey(blinding_key_hex, address2)
        self.log.info(f"Derived spending key for address_b: {spending_key[:16]}...")

        # Step 5: Build the scriptSig for the ELSE branch: <OP_FALSE>
        script_sig = "00"

        spend_amount = htlc_amount_btc - 0.01  # minus fee
        spend_inputs = [{
            "outid": out_hash,
            "value": amount_sats,
            "gamma": gamma_hex,
            "spending_key": spending_key,
            "scriptSig": script_sig,
            "sequence": htlc_locktime,
        }]
        spend_outputs = [{"address": address2, "amount": spend_amount}]

        # Step 6: Create spending tx. nSequence carries the per-input locktime
        # commitment (signature-bound via CTxIn::GetHash). CLTV checks
        # script_locktime <= input.nSequence; finality checks nSequence <= height.
        spend_raw = wallet2.createblsctrawtransaction(spend_inputs, spend_outputs)

        spend_funded = wallet2.fundblsctrawtransaction(spend_raw)
        spend_signed = wallet2.signblsctrawtransaction(spend_funded)

        balance2_before = wallet2.getbalance()

        spend_txid = self.nodes[0].sendrawtransaction(spend_signed)
        self.log.info(f"Timelock spend tx broadcast: {spend_txid}")

        self.generatetoblsctaddress(self.nodes[0], 1, address1)
        self.sync_blocks()

        balance2_after = wallet2.getbalance()
        self.log.info(f"Wallet2 balance before: {balance2_before}, after: {balance2_after}")
        assert_greater_than(balance2_after, balance2_before)

        self.log.info("=== HTLC timelock branch test PASSED ===")

    # ------------------------------------------------------------------
    # Helper: create an HTLC and build (but don't broadcast) a timelock
    # spending transaction.  Returns the signed spending tx hex.
    # ------------------------------------------------------------------
    def _build_timelock_spend(self, wallet_creator, wallet_spender,
                              addr_a, addr_b, locktime, sequence,
                              blinding_key_hex="03" * 32):
        secret = bytes([0xAB] * 32)
        secret_hash = hashlib.sha256(secret).digest()

        signed_tx = self._create_and_broadcast_htlc(
            wallet_creator, addr_a, addr_a, addr_b,
            1.0, secret_hash.hex(), locktime, blinding_key_hex)

        out_hash, amount_sats, gamma_hex = self._recover_htlc_output(
            wallet_creator, signed_tx, 1 * COIN)

        spending_key = wallet_spender.deriveblsctspendingkey(blinding_key_hex, addr_b)

        spend_inputs = [{
            "outid": out_hash,
            "value": amount_sats,
            "gamma": gamma_hex,
            "spending_key": spending_key,
            "scriptSig": "00",
            "sequence": sequence,
        }]
        spend_outputs = [{"address": addr_b, "amount": 0.99}]

        spend_raw = wallet_spender.createblsctrawtransaction(spend_inputs, spend_outputs)
        spend_funded = wallet_spender.fundblsctrawtransaction(spend_raw)
        return wallet_spender.signblsctrawtransaction(spend_funded)

    # ------------------------------------------------------------------
    # Boundary tests
    # ------------------------------------------------------------------
    def test_timelock_exact_boundary(self, wallet1, wallet2, address1, address2):
        """nSequence = L should be spendable at height L exactly."""
        self.log.info("=== Testing timelock exact boundary ===")

        current_height = self.nodes[0].getblockcount()
        htlc_locktime = current_height + 3

        spend_signed = self._build_timelock_spend(
            wallet1, wallet2, address1, address2,
            htlc_locktime, htlc_locktime, "04" * 32)

        blocks_needed = htlc_locktime - self.nodes[0].getblockcount()
        if blocks_needed > 0:
            self.generatetoblsctaddress(self.nodes[0], blocks_needed, address1)

        assert self.nodes[0].getblockcount() >= htlc_locktime

        txid = self.nodes[0].sendrawtransaction(spend_signed)
        self.log.info(f"Boundary spend accepted: {txid}")
        self.generatetoblsctaddress(self.nodes[0], 1, address1)
        self.sync_blocks()

        self.log.info("=== Timelock exact boundary test PASSED ===")

    def test_timelock_too_early(self, wallet1, wallet2, address1, address2):
        """Spending before the locktime height must be rejected."""
        self.log.info("=== Testing timelock too early ===")

        current_height = self.nodes[0].getblockcount()
        htlc_locktime = current_height + 50

        spend_signed = self._build_timelock_spend(
            wallet1, wallet2, address1, address2,
            htlc_locktime, htlc_locktime, "05" * 32)

        assert self.nodes[0].getblockcount() < htlc_locktime

        assert_raises_rpc_error(-26, "non-final-input",
                                self.nodes[0].sendrawtransaction, spend_signed)
        self.log.info("=== Timelock too-early test PASSED ===")

    def test_timelock_timestamp(self, wallet1, wallet2, address1, address2):
        """Timestamp-mode lock: nSequence >= LOCKTIME_THRESHOLD, checked
        against MTP.  Mine blocks until MTP exceeds the lock value."""
        self.log.info("=== Testing timestamp-based timelock ===")

        tip_hash = self.nodes[0].getbestblockhash()
        tip_mtp = self.nodes[0].getblockheader(tip_hash)["mediantime"]
        ts_lock = tip_mtp + 1

        self.log.info(f"Timestamp lock: {ts_lock} (current MTP: {tip_mtp})")
        assert ts_lock >= LOCKTIME_THRESHOLD, "MTP too low for timestamp mode"

        spend_signed = self._build_timelock_spend(
            wallet1, wallet2, address1, address2,
            ts_lock, ts_lock, "06" * 32)

        for _ in range(12):
            self.generatetoblsctaddress(self.nodes[0], 1, address1)
            tip_hash = self.nodes[0].getbestblockhash()
            tip_mtp = self.nodes[0].getblockheader(tip_hash)["mediantime"]
            if tip_mtp >= ts_lock:
                break

        assert tip_mtp >= ts_lock, f"MTP {tip_mtp} still below lock {ts_lock}"

        txid = self.nodes[0].sendrawtransaction(spend_signed)
        self.log.info(f"Timestamp spend accepted: {txid}")
        self.generatetoblsctaddress(self.nodes[0], 1, address1)
        self.sync_blocks()

        self.log.info("=== Timestamp timelock test PASSED ===")

    def test_timelock_timestamp_too_early(self, wallet1, wallet2, address1, address2):
        """Timestamp lock far in the future must be rejected."""
        self.log.info("=== Testing timestamp timelock too early ===")

        future_ts = int(time.time()) + 86400 * 365 * 5

        spend_signed = self._build_timelock_spend(
            wallet1, wallet2, address1, address2,
            future_ts, future_ts, "07" * 32)

        assert_raises_rpc_error(-26, "non-final-input",
                                self.nodes[0].sendrawtransaction, spend_signed)
        self.log.info("=== Timestamp too-early test PASSED ===")

    def test_sequence_final_cltv_fails(self, wallet1, wallet2, address1, address2):
        """SEQUENCE_FINAL + CLTV script must fail: CheckLockTime rejects
        SEQUENCE_FINAL because no locktime commitment is present."""
        self.log.info("=== Testing SEQUENCE_FINAL with CLTV ===")

        current_height = self.nodes[0].getblockcount()
        htlc_locktime = current_height + 2

        secret = bytes([0xCD] * 32)
        secret_hash = hashlib.sha256(secret).digest()
        blinding_key_hex = "08" * 32

        signed_tx = self._create_and_broadcast_htlc(
            wallet1, address1, address1, address2,
            1.0, secret_hash.hex(), htlc_locktime, blinding_key_hex)

        out_hash, amount_sats, gamma_hex = self._recover_htlc_output(
            wallet1, signed_tx, 1 * COIN)

        blocks_needed = htlc_locktime - self.nodes[0].getblockcount() + 1
        if blocks_needed > 0:
            self.generatetoblsctaddress(self.nodes[0], blocks_needed, address1)

        spending_key = wallet2.deriveblsctspendingkey(blinding_key_hex, address2)

        spend_inputs = [{
            "outid": out_hash,
            "value": amount_sats,
            "gamma": gamma_hex,
            "spending_key": spending_key,
            "scriptSig": "00",
            # No "sequence" field → defaults to SEQUENCE_FINAL (0xFFFFFFFF)
        }]
        spend_outputs = [{"address": address2, "amount": 0.99}]

        spend_raw = wallet2.createblsctrawtransaction(spend_inputs, spend_outputs)
        spend_funded = wallet2.fundblsctrawtransaction(spend_raw)
        spend_signed = wallet2.signblsctrawtransaction(spend_funded)

        assert_raises_rpc_error(-26, "failed-script-check",
                                self.nodes[0].sendrawtransaction, spend_signed)
        self.log.info("=== SEQUENCE_FINAL+CLTV test PASSED ===")

    def test_reserved_sequence_bits(self, wallet1, wallet2, address1, address2):
        """nSequence with bit 31 set (reserved) must be rejected at RPC."""
        self.log.info("=== Testing reserved sequence bits ===")

        current_height = self.nodes[0].getblockcount()
        htlc_locktime = current_height + 2
        reserved_seq = 0x80000000 | htlc_locktime

        secret = bytes([0xEE] * 32)
        secret_hash = hashlib.sha256(secret).digest()
        blinding_key_hex = "09" * 32

        signed_tx = self._create_and_broadcast_htlc(
            wallet1, address1, address1, address2,
            1.0, secret_hash.hex(), htlc_locktime, blinding_key_hex)

        out_hash, amount_sats, gamma_hex = self._recover_htlc_output(
            wallet1, signed_tx, 1 * COIN)

        spending_key = wallet2.deriveblsctspendingkey(blinding_key_hex, address2)

        spend_inputs = [{
            "outid": out_hash,
            "value": amount_sats,
            "gamma": gamma_hex,
            "spending_key": spending_key,
            "scriptSig": "00",
            "sequence": reserved_seq,
        }]
        spend_outputs = [{"address": address2, "amount": 0.99}]

        assert_raises_rpc_error(-8, "reserved",
                                wallet2.createblsctrawtransaction,
                                spend_inputs, spend_outputs)
        self.log.info("=== Reserved sequence bits test PASSED ===")

    def test_height_time_mode_mismatch(self, wallet1, wallet2, address1, address2):
        """Height-mode locktime in script with time-mode nSequence (or vice
        versa) must fail the type-consistency check in CheckLockTime."""
        self.log.info("=== Testing height/time mode mismatch ===")

        current_height = self.nodes[0].getblockcount()
        htlc_locktime = current_height + 2

        tip_hash = self.nodes[0].getbestblockhash()
        tip_mtp = self.nodes[0].getblockheader(tip_hash)["mediantime"]
        time_seq = tip_mtp - 100
        assert time_seq >= LOCKTIME_THRESHOLD

        spend_signed = self._build_timelock_spend(
            wallet1, wallet2, address1, address2,
            htlc_locktime, time_seq, "0a" * 32)

        blocks_needed = htlc_locktime - self.nodes[0].getblockcount() + 1
        if blocks_needed > 0:
            self.generatetoblsctaddress(self.nodes[0], blocks_needed, address1)

        assert_raises_rpc_error(-26, "failed-script-check",
                                self.nodes[0].sendrawtransaction, spend_signed)
        self.log.info("=== Height/time mode mismatch test PASSED ===")

    def test_importblsctscript(self, wallet1, wallet2, address1, address2):
        """Test that importblsctscript lets the receiver detect an HTLC
        output on-chain without receiving any out-of-band data beyond the
        initial negotiation parameters."""
        self.log.info("=== Testing importblsctscript ===")

        secret = bytes([0x42] * 32)
        secret_hash = hashlib.sha256(secret).digest()
        blinding_key_hex = "bb" * 32
        current_height = self.nodes[0].getblockcount()
        htlc_locktime = current_height + 50
        htlc_amount_btc = 1.0
        htlc_amount_sats = int(htlc_amount_btc * COIN)

        # Receiver (wallet2) imports the expected HTLC script BEFORE it exists
        result = wallet2.importblsctscript({
            "type": "atomic_swap",
            "address_a": address1,
            "address_b": address2,
            "hash": secret_hash.hex(),
            "locktime": htlc_locktime,
            "blinding_key": blinding_key_hex,
        }, False)  # rescan=False, nothing to find yet
        assert result["success"]
        imported_script = result["script"]
        self.log.info(f"Imported HTLC script: {imported_script[:40]}...")

        # Funder (wallet1) creates and broadcasts the HTLC
        signed_tx = self._create_and_broadcast_htlc(
            wallet1, address1, address1, address2,
            htlc_amount_btc, secret_hash.hex(), htlc_locktime, blinding_key_hex)

        # Sync node1 so wallet2 sees the new block
        self.sync_blocks()

        # Wallet2 should now detect the HTLC output via the watch-only match.
        # listblsctunspent includes watch-only entries with watchonly=true.
        unspent = wallet2.listblsctunspent()
        htlc_matches = [u for u in unspent
                        if u.get("scriptPubKey") == imported_script]
        assert len(htlc_matches) > 0, (
            f"Receiver did not detect HTLC output via listblsctunspent. "
            f"Got {len(unspent)} outputs, none matched script {imported_script[:40]}...")
        htlc_utxo = htlc_matches[0]
        assert htlc_utxo.get("watchonly"), "HTLC output should be marked watchonly"
        self.log.info(f"Receiver detected HTLC output: {htlc_utxo['outid']}")

        # Also test raw script import
        raw_result = wallet2.importblsctscript({
            "type": "raw",
            "script": "51",  # OP_TRUE
        }, False)
        assert raw_result["success"]
        assert raw_result["script"] == "51"
        self.log.info("Raw script import succeeded")

        self.log.info("=== importblsctscript test PASSED ===")


if __name__ == '__main__':
    BLSCTHTLCTest().main()
