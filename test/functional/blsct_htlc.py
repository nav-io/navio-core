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
- In the current `atomic_swap` implementation, the blinded output itself is
  constructed against `address_a`'s BLSCT destination. Shared-nonce recovery
  therefore uses `address_a`, not `address_b`.
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
   The funder chooses a random 32-byte `blinding_key` locally when constructing
   the output. The owner of `address_a` can later recover the HTLC output via
   the normal `getblsctrecoverydata` path because the current `atomic_swap`
   implementation blinds the output against `address_a`. A different party that
   does not own `address_a` can still recover later if it retained or received
   the `blinding_key`, by deriving the shared public nonce from
   `address_a + blinding_key`.
2. Create the HTLC output:

       wallet.createblsctrawtransaction(
           [],
           [{
               "type": "atomic_swap",
               "address_a": address_a,
               "address_b": address_b,
               "amount": amount_sats,
               "hash": secret_hash_hex,
               "locktime": locktime,
               "blinding_key": blinding_key_hex,
           }],
       )

3. Add wallet-selected fee inputs and change with `fundblsctrawtransaction`.
4. Sign it with `signblsctrawtransaction`.
5. If you own `address_a`, recover the HTLC output data directly:

       recovery = wallet.getblsctrecoverydata(signed_tx_hex)

6. If you do not own `address_a`, derive the recovery nonce from
   `address_a` and `blinding_key`:

       nonce_hex = wallet.deriveblsctnonce(blinding_key_hex, address_a)

7. Then recover the HTLC output data from the signed tx hex:

       recovery = wallet.getblsctrecoverydatawithnonce(signed_tx_hex, nonce_hex)

8. Optionally preflight with `testmempoolaccept`.
9. Broadcast with `sendrawtransaction`.

Counterparty detection sequence
-------------------------------

The counterparty does **not** need to receive the raw transaction hex. After
the initial negotiation (step 1), they import the expected HTLC
script into their wallet so it is detected automatically during block
scanning:

    counterparty_wallet.importblsctscript({
        "type": "atomic_swap",
        "address_a": address_a,
        "address_b": address_b,
        "hash": secret_hash_hex,
        "locktime": locktime,
        "blinding_key": blinding_key_hex,
    })

Once the funder broadcasts and the output is mined, the counterparty wallet
picks it up via the watch-only script match. The counterparty finds the
output by calling `listblsctunspent`, which includes watch-only entries
with `watchonly: true`:

    utxos = counterparty_wallet.listblsctunspent()
    htlc_utxos = [u for u in utxos if u.get("watchonly")]

Each entry contains `outid` (the output hash) and `scriptPubKey`.
If the counterparty does not own `address_a`, it can derive the shared
public nonce and recover `amount` and `gamma` from the output using
`getblsctrecoverydatawithnonce`:

    nonce_hex = counterparty_wallet.deriveblsctnonce(blinding_key_hex, address_a)
    recovery = counterparty_wallet.getblsctrecoverydatawithnonce(utxo["outid"], nonce_hex)

Arbitrary (non-HTLC) scripts can also be imported in raw hex form:

    wallet.importblsctscript({"type": "raw", "script": "<hex>"})

Important units
---------------

- All blsctraw RPC amounts (`amount` for outputs, `value` for inputs) are
  expressed in navoshis.
- `getblsctrecoverydata` and `getblsctrecoverydatawithnonce` both return
  `amount` (in NAV) and `amount_navoshi` (in navoshis). Use
  `amount_navoshi` directly as an input `value`.

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
           [{"address": destination, "amount": spend_amount_sats}],
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
           [{"address": destination, "amount": spend_amount_sats}],
       )

5. Fund it with `fundblsctrawtransaction`.
6. Sign it with `signblsctrawtransaction`.
7. Optionally preflight with `testmempoolaccept`.
8. Broadcast with `sendrawtransaction`.

Common failure cases
--------------------

- Omitting `sequence` on the timelock branch leaves `SEQUENCE_FINAL`
  (`0xFFFFFFFF`), which causes CLTV script validation to fail.
- Passing the 32-byte `blinding_key` directly to
  `getblsctrecoverydatawithnonce` is wrong. First derive the shared public
  nonce with `deriveblsctnonce(blinding_key, address_a)`.
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
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_greater_than, assert_raises_rpc_error
from test_framework.messages import COIN

LOCKTIME_THRESHOLD = 500_000_000
WALLET1_SEED_WIF = "cS9umN9w6cDMuRVYdbkfE4c7YUFLJRoXMfhQ569uY4odiQbVN8Rt"
WALLET2_SEED_WIF = "cTdGmKFWpbvpKQ7ejrdzqYT2hhjyb3GPHnLAK7wdi5Em67YLwSm9"


class BLSCTHTLCTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def run_test(self):
        self.log.info("Setting up wallets and generating initial blocks")

        # Create a non-participating miner wallet to fund the test wallets.
        self.nodes[0].createwallet(wallet_name="miner", blsct=True)
        miner = self.nodes[0].get_wallet_rpc("miner")
        miner_addr = miner.getnewaddress(label="", address_type="blsct")

        # Create blank BLSCT wallets, then set their seeds explicitly.
        self.nodes[0].createwallet(wallet_name="wallet1", blsct=True, blank=True)
        self.nodes[1].createwallet(wallet_name="wallet2", blsct=True, blank=True)

        wallet1 = self.nodes[0].get_wallet_rpc("wallet1")
        wallet2 = self.nodes[1].get_wallet_rpc("wallet2")

        wallet1.setblsctseed(WALLET1_SEED_WIF)
        wallet2.setblsctseed(WALLET2_SEED_WIF)

        address1 = wallet1.getnewaddress(label="", address_type="blsct")
        address2 = wallet2.getnewaddress(label="", address_type="blsct")

        # Mine blocks to the miner wallet, then fund the participating wallets.
        fund_wallet1_amount = 50
        fund_wallet2_amount = 10
        required_miner_balance = fund_wallet1_amount + fund_wallet2_amount + 1

        self.log.info("Generating initial blocks to fund miner wallet")
        self.generatetoblsctaddress(self.nodes[0], 101, miner_addr)

        miner_balance = miner.getbalance()
        while miner_balance < required_miner_balance:
            self.log.info(
                "Miner spendable balance %s is below required %s, mining one more block",
                miner_balance,
                required_miner_balance,
            )
            self.generatetoblsctaddress(self.nodes[0], 1, miner_addr)
            miner_balance = miner.getbalance()

        self.log.info("Funding wallet1 from miner wallet")
        miner.sendtoblsctaddress(address1, fund_wallet1_amount)
        self.generatetoblsctaddress(self.nodes[0], 1, miner_addr)

        self.log.info("Funding wallet2 from miner wallet")
        miner.sendtoblsctaddress(address2, fund_wallet2_amount)
        self.generatetoblsctaddress(self.nodes[0], 1, miner_addr)
        self.sync_blocks()

        # Store miner address for use in block generation throughout the tests.
        self.miner_addr = miner_addr

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

    def _create_and_broadcast_htlc(self, wallet, address_a, address_b,
                                    amount_sats, secret_hash_hex, locktime, blinding_key_hex):
        """Create, fund, sign and broadcast an HTLC output.
        Returns the signed transaction hex."""
        outputs = [{
            "type": "atomic_swap",
            "address_a": address_a,
            "address_b": address_b,
            "amount": amount_sats,
            "hash": secret_hash_hex,
            "locktime": locktime,
            "blinding_key": blinding_key_hex,
        }]

        raw_tx = wallet.createblsctrawtransaction([], outputs)
        funded_tx = wallet.fundblsctrawtransaction(raw_tx)
        signed_tx = wallet.signblsctrawtransaction(funded_tx)
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.log.info(f"HTLC creation tx broadcast: {txid}")
        self.generatetoblsctaddress(self.nodes[0], 1, self.miner_addr)
        return signed_tx

    def _recover_htlc_output(self, wallet, signed_tx_hex, expected_amount_sats):
        """Recover the HTLC output from raw tx hex via the owning wallet."""
        recovery = wallet.getblsctrecoverydata(signed_tx_hex)
        for out in recovery["outputs"]:
            recovered_sats = out["amount_navoshi"]
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

        self.log.info(f"Secret hash: {secret_hash.hex()}")
        self.log.info(f"HTLC locktime: {htlc_locktime} (current height: {current_height})")

        # Step 1: Create and broadcast the HTLC output
        signed_tx = self._create_and_broadcast_htlc(
            wallet1, address1, address2,
            htlc_amount_sats, secret_hash.hex(), htlc_locktime, blinding_key_hex)

        # Step 2: Recover the HTLC output data. wallet1 owns address_a, so the
        # standard wallet recovery path works.
        out_hash, amount_sats, gamma_hex = self._recover_htlc_output(
            wallet1, signed_tx, htlc_amount_sats)
        self.log.info(f"HTLC output: hash={out_hash}, amount={amount_sats}, gamma={gamma_hex[:16]}...")

        # Step 3: Derive spending key for address_a (hashlock claimant)
        spending_key = wallet1.deriveblsctspendingkey(blinding_key_hex, address1)
        self.log.info(f"Derived spending key for address_a: {spending_key[:16]}...")

        # Step 4: Build the scriptSig for the IF branch: <push 32-byte secret> <OP_TRUE>
        script_sig = "20" + secret.hex() + "51"

        spend_amount_sats = htlc_amount_sats - COIN // 100  # minus 0.01 fee
        spend_inputs = [{
            "outid": out_hash,
            "value": amount_sats,
            "gamma": gamma_hex,
            "spending_key": spending_key,
            "scriptSig": script_sig,
        }]
        spend_outputs = [{"address": address1, "amount": spend_amount_sats}]

        # Step 5: Create, fund, sign and broadcast the spending transaction
        spend_raw = wallet1.createblsctrawtransaction(spend_inputs, spend_outputs)
        spend_funded = wallet1.fundblsctrawtransaction(spend_raw)
        spend_signed = wallet1.signblsctrawtransaction(spend_funded)

        balance_before = wallet1.getbalance()
        spend_txid = self.nodes[0].sendrawtransaction(spend_signed)
        self.log.info(f"Hashlock spend tx broadcast: {spend_txid}")

        self.generatetoblsctaddress(self.nodes[0], 1, self.miner_addr)

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

        self.log.info(f"HTLC locktime: {htlc_locktime} (current height: {current_height})")

        # Step 1: Create and broadcast the HTLC output
        signed_tx = self._create_and_broadcast_htlc(
            wallet1, address1, address2,
            htlc_amount_sats, secret_hash.hex(), htlc_locktime, blinding_key_hex)

        # Step 2: Recover the HTLC output data. wallet1 owns address_a, so the
        # standard wallet recovery path works.
        out_hash, amount_sats, gamma_hex = self._recover_htlc_output(
            wallet1, signed_tx, htlc_amount_sats)
        self.log.info(f"HTLC output: hash={out_hash}, amount={amount_sats}")

        # Step 3: Mine blocks until the locktime is reached
        blocks_to_mine = htlc_locktime - self.nodes[0].getblockcount() + 1
        self.log.info(f"Mining {blocks_to_mine} blocks to reach locktime {htlc_locktime}")
        self.generatetoblsctaddress(self.nodes[0], blocks_to_mine, self.miner_addr)

        current_height = self.nodes[0].getblockcount()
        self.log.info(f"Current height after mining: {current_height}")
        assert_greater_than(current_height, htlc_locktime - 1)

        # Step 4: Derive spending key for address_b (timelock claimant).
        # Wallet2 owns address_b and knows the blinding key (shared off-chain).
        spending_key = wallet2.deriveblsctspendingkey(blinding_key_hex, address2)
        self.log.info(f"Derived spending key for address_b: {spending_key[:16]}...")

        # Step 5: Build the scriptSig for the ELSE branch: <OP_FALSE>
        script_sig = "00"

        spend_amount_sats = htlc_amount_sats - COIN // 100  # minus 0.01 fee
        spend_inputs = [{
            "outid": out_hash,
            "value": amount_sats,
            "gamma": gamma_hex,
            "spending_key": spending_key,
            "scriptSig": script_sig,
            "sequence": htlc_locktime,
        }]
        spend_outputs = [{"address": address2, "amount": spend_amount_sats}]

        # Step 6: Create spending tx. nSequence carries the per-input locktime
        # commitment (signature-bound via CTxIn::GetHash). CLTV checks
        # script_locktime <= input.nSequence; finality checks nSequence <= height.
        spend_raw = wallet2.createblsctrawtransaction(spend_inputs, spend_outputs)

        spend_funded = wallet2.fundblsctrawtransaction(spend_raw)
        spend_signed = wallet2.signblsctrawtransaction(spend_funded)

        balance2_before = wallet2.getbalance()

        spend_txid = self.nodes[0].sendrawtransaction(spend_signed)
        self.log.info(f"Timelock spend tx broadcast: {spend_txid}")

        self.generatetoblsctaddress(self.nodes[0], 1, self.miner_addr)
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
            wallet_creator, addr_a, addr_b,
            1 * COIN, secret_hash.hex(), locktime, blinding_key_hex)

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
        spend_outputs = [{"address": addr_b, "amount": 99000000}]

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
            self.generatetoblsctaddress(self.nodes[0], blocks_needed, self.miner_addr)

        assert self.nodes[0].getblockcount() >= htlc_locktime

        txid = self.nodes[0].sendrawtransaction(spend_signed)
        self.log.info(f"Boundary spend accepted: {txid}")
        self.generatetoblsctaddress(self.nodes[0], 1, self.miner_addr)
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
            self.generatetoblsctaddress(self.nodes[0], 1, self.miner_addr)
            tip_hash = self.nodes[0].getbestblockhash()
            tip_mtp = self.nodes[0].getblockheader(tip_hash)["mediantime"]
            if tip_mtp >= ts_lock:
                break

        assert tip_mtp >= ts_lock, f"MTP {tip_mtp} still below lock {ts_lock}"

        txid = self.nodes[0].sendrawtransaction(spend_signed)
        self.log.info(f"Timestamp spend accepted: {txid}")
        self.generatetoblsctaddress(self.nodes[0], 1, self.miner_addr)
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
            wallet1, address1, address2,
            1 * COIN, secret_hash.hex(), htlc_locktime, blinding_key_hex)

        out_hash, amount_sats, gamma_hex = self._recover_htlc_output(
            wallet1, signed_tx, 1 * COIN)

        blocks_needed = htlc_locktime - self.nodes[0].getblockcount() + 1
        if blocks_needed > 0:
            self.generatetoblsctaddress(self.nodes[0], blocks_needed, self.miner_addr)

        spending_key = wallet2.deriveblsctspendingkey(blinding_key_hex, address2)

        spend_inputs = [{
            "outid": out_hash,
            "value": amount_sats,
            "gamma": gamma_hex,
            "spending_key": spending_key,
            "scriptSig": "00",
            # No "sequence" field → defaults to SEQUENCE_FINAL (0xFFFFFFFF)
        }]
        spend_outputs = [{"address": address2, "amount": 99000000}]

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
            wallet1, address1, address2,
            1 * COIN, secret_hash.hex(), htlc_locktime, blinding_key_hex)

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
        spend_outputs = [{"address": address2, "amount": 99000000}]

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
            self.generatetoblsctaddress(self.nodes[0], blocks_needed, self.miner_addr)

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
        htlc_amount_sats = 1 * COIN
        script_descriptor = {
            "type": "atomic_swap",
            "address_a": address1,
            "address_b": address2,
            "hash": secret_hash.hex(),
            "locktime": htlc_locktime,
            "blinding_key": blinding_key_hex,
        }

        # Counterparty (wallet2) imports the expected HTLC script BEFORE it exists
        result = wallet2.importblsctscript(script_descriptor, False)  # rescan=False, nothing to find yet
        assert result["success"]
        imported_script = result["script"]
        self.log.info(f"Imported HTLC script: {imported_script[:40]}...")

        # Funder (wallet1) creates and broadcasts the HTLC
        self._create_and_broadcast_htlc(
            wallet1, address1, address2,
            htlc_amount_sats, secret_hash.hex(), htlc_locktime, blinding_key_hex)

        # Sync node1 so wallet2 sees the new block
        self.sync_blocks()

        # Wallet2 should now detect the HTLC output via the watch-only match.
        # listblsctunspent includes watch-only entries with watchonly=true.
        unspent = wallet2.listblsctunspent()
        htlc_matches = [u for u in unspent
                        if u.get("scriptPubKey") == imported_script]
        assert len(htlc_matches) > 0, (
            f"Counterparty did not detect HTLC output via listblsctunspent. "
            f"Got {len(unspent)} outputs, none matched script {imported_script[:40]}...")
        htlc_utxo = htlc_matches[0]
        assert htlc_utxo.get("watchonly"), "HTLC output should be marked watchonly"
        assert htlc_utxo["amount"] == Decimal("1"), "Imported HTLC output should have recovered amount in output storage"
        self.log.info(f"Counterparty detected HTLC output: {htlc_utxo['outid']}")

        stored_recovery = wallet2.getblsctrecoverydata(htlc_utxo["outid"])
        stored_outputs = [out for out in stored_recovery["outputs"] if out["out_hash"] == htlc_utxo["outid"]]
        assert len(stored_outputs) == 1, (
            f"Counterparty did not recover HTLC output into output storage. "
            f"Recovery data: {stored_recovery['outputs']}")
        assert stored_outputs[0]["amount_navoshi"] == htlc_amount_sats
        assert stored_outputs[0]["gamma"] != ""
        self.log.info("Counterparty recovered HTLC output into watch-only output storage")

        nonce_hex = wallet2.deriveblsctnonce(blinding_key_hex, address1)
        recovery = wallet2.getblsctrecoverydatawithnonce(htlc_utxo["outid"], nonce_hex)
        recovered = [out for out in recovery["outputs"] if out["out_hash"] == htlc_utxo["outid"]]
        assert len(recovered) == 1, (
            f"Counterparty did not recover HTLC output via derived nonce. "
            f"Recovery data: {recovery['outputs']}")
        assert recovered[0]["amount_navoshi"] == htlc_amount_sats
        assert recovered[0]["gamma"] != ""
        self.log.info("Counterparty recovered HTLC output via derived shared public nonce")

        # Fresh wallets importing after the HTLC exists should respect start_height.
        # _create_and_broadcast_htlc mines the funding tx into the current tip.
        htlc_block_height = self.nodes[0].getblockcount()
        self.generatetoblsctaddress(self.nodes[0], 1, self.miner_addr)

        self.nodes[1].createwallet(wallet_name="wallet2_rescan_hit", blsct=True, blank=True)
        self.nodes[1].createwallet(wallet_name="wallet2_rescan_miss", blsct=True, blank=True)
        wallet2_rescan_hit = self.nodes[1].get_wallet_rpc("wallet2_rescan_hit")
        wallet2_rescan_miss = self.nodes[1].get_wallet_rpc("wallet2_rescan_miss")

        hit_result = wallet2_rescan_hit.importblsctscript(script_descriptor, True, htlc_block_height)
        assert hit_result["success"]
        hit_matches = [
            u for u in wallet2_rescan_hit.listblsctunspent()
            if u.get("scriptPubKey") == hit_result["script"]
        ]
        assert len(hit_matches) > 0, "Rescan from the HTLC block height should find the imported output"

        miss_result = wallet2_rescan_miss.importblsctscript(script_descriptor, True, htlc_block_height + 1)
        assert miss_result["success"]
        miss_matches = [
            u for u in wallet2_rescan_miss.listblsctunspent()
            if u.get("scriptPubKey") == miss_result["script"]
        ]
        assert len(miss_matches) == 0, "Rescan from a later height should not find the historical HTLC output"
        self.log.info("Height-based importblsctscript rescan start works as expected")

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
