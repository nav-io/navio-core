#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Regression tests for two BLSCT send-path gaps:

A. `subtractfeefromamount` was a no-op on the BLSCT send path: the recipient
   received the full amount whether or not the flag was set. It must now reduce
   the recipient's output by the whole transaction fee (so the wallet spends
   exactly the requested amount).

B. `comment` / `comment_to` passed to `sendtoaddress` (or `comment_to` to
   `sendtoblsctaddress`) were dropped for BLSCT wallets, so `listtransactions`
   never surfaced them for the sender. They must now be stored on the sender's
   transaction and returned by `listtransactions`.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class BlsctSubtractFeeCommentTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="sender", blsct=True)
        node.createwallet(wallet_name="receiver", blsct=True)
        self.sender = node.get_wallet_rpc("sender")
        self.receiver = node.get_wallet_rpc("receiver")

        self.mining_addr = self.sender.getnewaddress(label="", address_type="blsct")
        self.generatetoblsctaddress(node, 120, self.mining_addr)

        self.test_subtractfeefromamount()
        self.test_comment_fields_via_sendtoaddress()
        self.test_comment_to_via_sendtoblsctaddress()

    def _received(self, addr):
        rows = self.receiver.listreceivedbyaddress(0, True)
        row = next((r for r in rows if r["address"] == addr), None)
        return Decimal(str(row["amount"])) if row is not None else Decimal(0)

    def test_subtractfeefromamount(self):
        self.log.info("A: subtractfeefromamount reduces the recipient's amount")

        amount = Decimal("10")

        # Baseline: without the flag the receiver gets exactly the full amount.
        addr_full = self.receiver.getnewaddress(label="", address_type="blsct")
        self.sender.sendtoaddress(addr_full, amount)
        self.generatetoblsctaddress(self.nodes[0], 1, self.mining_addr)
        received_full = self._received(addr_full)
        assert_equal(received_full, amount)

        # With the flag the receiver gets strictly less: the fee is taken out of
        # the output rather than added on top.
        addr_sub = self.receiver.getnewaddress(label="", address_type="blsct")
        self.sender.sendtoaddress(addr_sub, amount, "", "", True)
        self.generatetoblsctaddress(self.nodes[0], 1, self.mining_addr)
        received_sub = self._received(addr_sub)

        fee = amount - received_sub
        assert_greater_than(fee, Decimal(0))          # a real fee was subtracted
        assert_greater_than(received_sub, Decimal(0))  # but not the whole amount
        assert_greater_than(amount, received_sub)      # strictly less than requested
        # Sanity: the subtracted fee is a small transaction fee, not a huge value.
        assert_greater_than(Decimal("0.1"), fee)
        self.log.info(f"receiver got {received_sub} of {amount} (fee {fee} subtracted)")

        # The sendtoblsctaddress subtractfeefromamount arg (positional) behaves
        # identically.
        addr_direct = self.receiver.getnewaddress(label="", address_type="blsct")
        self.sender.sendtoblsctaddress(addr_direct, amount, "", False, True)
        self.generatetoblsctaddress(self.nodes[0], 1, self.mining_addr)
        assert_greater_than(amount, self._received(addr_direct))

    def _find_send_row(self, wallet, comment):
        for e in wallet.listtransactions("*", 1000, 0, True):
            if e.get("category") == "send" and e.get("comment") == comment:
                return e
        return None

    def test_comment_fields_via_sendtoaddress(self):
        self.log.info("B: sendtoaddress comment/comment_to reach listtransactions")

        addr = self.receiver.getnewaddress(label="", address_type="blsct")
        self.sender.sendtoaddress(addr, Decimal("1"), "invoice-42", "Acme Corp")
        self.generatetoblsctaddress(self.nodes[0], 1, self.mining_addr)

        row = self._find_send_row(self.sender, "invoice-42")
        assert row is not None, "send row with comment 'invoice-42' not found in listtransactions"
        assert_equal(row.get("comment"), "invoice-42")
        assert_equal(row.get("to"), "Acme Corp")

    def test_comment_to_via_sendtoblsctaddress(self):
        self.log.info("B: sendtoblsctaddress comment_to reaches listtransactions")

        addr = self.receiver.getnewaddress(label="", address_type="blsct")
        # positional: address, amount, memo, verbose, subtractfeefromamount, comment_to
        self.sender.sendtoblsctaddress(addr, Decimal("1"), "memo-note", False, False, "Bob")
        self.generatetoblsctaddress(self.nodes[0], 1, self.mining_addr)

        row = self._find_send_row(self.sender, "memo-note")
        assert row is not None, "send row with comment 'memo-note' not found in listtransactions"
        assert_equal(row.get("comment"), "memo-note")
        assert_equal(row.get("to"), "Bob")


if __name__ == '__main__':
    BlsctSubtractFeeCommentTest(__file__).main()
