#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Regression tests for BLSCT listtransactions / listreceivedbyaddress around
stakelock / stakeunlock.

Covers three bugs:

A. `listtransactions *` was hiding mempool receive/stake rows while still
   emitting the matching send row. A just-broadcast `stakelock` looked like
   coins had left the wallet until confirmation.

B. `listreceivedbyaddress` iterated only CWalletTx. Under output-storage,
   self-generated receive addresses whose credits live in mapOutputs only
   showed amount=0.

C. `stakeunlock` called `GetNewDestination(BLSCT_STAKE, "")`, which clobbered
   the address-book label of the (single) BLSCT staking account with an
   empty string. After the first unlock, the stake address — still valid,
   still reused for any remaining stake portion — lost its "Locked Stake"
   label.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class BlsctListTransactionsStakeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=2):
        blocks = []
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            blocks.extend(self.generatetoblsctaddress(node, to_generate, address))
            remaining -= to_generate
        return blocks

    def run_test(self):
        self.min_stake = 100

        self.nodes[0].createwallet(wallet_name="w", blsct=True, storage_output=True)
        self.wallet = self.nodes[0].get_wallet_rpc("w")
        self.mining_addr = self.wallet.getnewaddress(label="", address_type="blsct")

        # Mine enough to mature rewards and exceed the 2 * min_stake buffer we
        # need for partial-unlock scenarios.
        self.generate_blsct_blocks(self.nodes[0], self.mining_addr, 210)

        self.test_mempool_stakelock_visible()
        self.test_listreceivedbyaddress_credits_user_generated_address()
        self.test_stakeunlock_preserves_label()

    # --- Bug A + C: stakelock in mempool is visible; label set ---

    def test_mempool_stakelock_visible(self):
        self.log.info("Bug A: listtransactions shows mempool stakelock on all sides")

        stake_amount = Decimal("100")
        self.wallet.stakelock(stake_amount)

        # Unconfirmed. Pre-fix only the send row surfaced.
        mempool_entries = self.wallet.listtransactions("*", 100000, 0, True)
        mempool_unconfirmed = [e for e in mempool_entries if e.get("confirmations", 0) == 0]

        send_rows = [e for e in mempool_unconfirmed if e.get("category") == "send"]
        stake_rows = [e for e in mempool_unconfirmed if e.get("category") == "stake"]

        assert_greater_than(len(send_rows), 0)
        assert len(stake_rows) >= 1, (
            "mempool stakelock must surface as category=stake in listtransactions; "
            f"got {mempool_unconfirmed}"
        )

        # Confirm and continue with remaining tests.
        self.generate_blsct_blocks(self.nodes[0], self.mining_addr, 1)

    # --- Bug B: listreceivedbyaddress credits output-storage receives ---

    def test_listreceivedbyaddress_credits_user_generated_address(self):
        self.log.info("Bug B: listreceivedbyaddress tallies mapOutputs credits")

        # Fresh destination owned by the same wallet. Pre-fix the receive-side
        # credit lived in mapOutputs only and listreceivedbyaddress returned 0.
        recv_addr = self.wallet.getnewaddress(label="", address_type="blsct")

        self.wallet.sendtoblsctaddress(recv_addr, Decimal("5"))
        self.generate_blsct_blocks(self.nodes[0], self.mining_addr, 1)

        rows = self.wallet.listreceivedbyaddress(0, True)
        row = next((r for r in rows if r["address"] == recv_addr), None)
        assert row is not None, f"listreceivedbyaddress did not include {recv_addr}"
        assert_equal(Decimal(str(row["amount"])), Decimal("5"))
        assert_greater_than(row["confirmations"], 0)
        assert len(row["txids"]) >= 1

    # --- Bug C: stakeunlock must not clobber the stake-address label ---

    def test_stakeunlock_preserves_label(self):
        self.log.info("Bug C: stakeunlock preserves 'Locked Stake' label")

        # Read the stake-account address by locking once (same account every
        # time — BLSCT_STAKE is a single-destination account).
        self.wallet.stakelock(Decimal("200"))
        self.generate_blsct_blocks(self.nodes[0], self.mining_addr, 1)

        rows_before = self.wallet.listreceivedbyaddress(0, True)
        stake_rows_before = [r for r in rows_before if r.get("label") == "Locked Stake"]
        assert len(stake_rows_before) == 1, (
            f"expected exactly one 'Locked Stake' row after lock, got {stake_rows_before}"
        )
        stake_addr = stake_rows_before[0]["address"]

        # Partial unlock: leaves a remaining stake output on the same stake
        # address. Pre-fix the SetAddressBook call inside stakeunlock wrote
        # label="" to that address, wiping the "Locked Stake" label.
        self.wallet.stakeunlock(Decimal("100"))
        self.generate_blsct_blocks(self.nodes[0], self.mining_addr, 1)

        rows_after = self.wallet.listreceivedbyaddress(0, True)
        stake_row_after = next((r for r in rows_after if r["address"] == stake_addr), None)
        assert stake_row_after is not None, (
            f"stake address {stake_addr} disappeared from listreceivedbyaddress"
        )
        assert_equal(stake_row_after["label"], "Locked Stake")


if __name__ == '__main__':
    BlsctListTransactionsStakeTest().main()
