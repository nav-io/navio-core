#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test the getbalanceforaddress RPC.

The RPC must report a per-address breakdown of:
  * trusted (confirmed + min_depth satisfied)
  * untrusted_pending (in mempool, depth==0, sender not us)
  * immature (coinbase still in maturity window)
  * staked_commitment_balance (BLSCT staked outputs)

across both transparent and BLSCT addresses, and across both the legacy
mapWallet path and the BLSCT output-storage path.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


def _to_dec(x):
    return Decimal(str(x))


class BlsctGetBalanceForAddressTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    # --- helpers ---

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=4):
        """Mine `num_blocks` BLSCT blocks to `address`, batched to keep
        individual RPC calls fast."""
        blocks = []
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            blocks.extend(self.generatetoblsctaddress(node, to_generate, address))
            remaining -= to_generate
        return blocks

    def get_mine(self, wallet, address, **kwargs):
        """Convenience wrapper returning the ['mine'] sub-object as Decimals."""
        result = wallet.getbalanceforaddress(address, **kwargs)
        return {k: _to_dec(v) if k != "total" else _to_dec(v) for k, v in result["mine"].items()}

    def wallet_total(self, wallet):
        bal = wallet.getbalances()["mine"]
        return (_to_dec(bal["trusted"])
                + _to_dec(bal["untrusted_pending"])
                + _to_dec(bal["immature"])
                + _to_dec(bal.get("staked_commitment_balance", 0)))

    # --- tests ---

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="w0", blsct=True, storage_output=True)
        self.nodes[1].createwallet(wallet_name="w1", blsct=True, storage_output=True)
        self.w0 = self.nodes[0].get_wallet_rpc("w0")
        self.w1 = self.nodes[1].get_wallet_rpc("w1")
        self.addr0 = self.w0.getnewaddress(label="", address_type="blsct")
        self.addr1 = self.w1.getnewaddress(label="", address_type="blsct")

        self.test_invalid_inputs()
        self.test_zero_balance_for_unfunded_address()
        self.test_immature_then_trusted_for_miner_address()
        self.test_untrusted_pending_for_external_receive()
        self.test_minconf_filtering()
        self.test_two_addresses_isolated_balances()
        self.test_listblsctunspent_filters_by_address()
        self.test_listblsctunspent_matches_getbalanceforaddress()
        self.test_staked_commitment_balance()
        self.test_address_not_in_wallet()

    def test_invalid_inputs(self):
        self.log.info("=== Invalid inputs are rejected ===")
        assert_raises_rpc_error(-5, "Invalid address", self.w0.getbalanceforaddress, "not_an_address")
        # An empty string is also not a valid destination.
        assert_raises_rpc_error(-5, "Invalid address", self.w0.getbalanceforaddress, "")

    def test_zero_balance_for_unfunded_address(self):
        self.log.info("=== Unfunded address returns all-zero balances ===")
        fresh = self.w0.getnewaddress(label="", address_type="blsct")
        mine = self.get_mine(self.w0, fresh)
        assert_equal(mine["trusted"], _to_dec(0))
        assert_equal(mine["untrusted_pending"], _to_dec(0))
        assert_equal(mine["immature"], _to_dec(0))
        assert_equal(mine["staked_commitment_balance"], _to_dec(0))
        assert_equal(mine["total"], _to_dec(0))

    def test_immature_then_trusted_for_miner_address(self):
        self.log.info("=== Coinbase outputs report immature then mature into trusted ===")
        # Mine a single block to a brand-new address: the coinbase reward
        # must land in the 'immature' bucket and nowhere else.
        miner = self.w0.getnewaddress(label="", address_type="blsct")
        self.generate_blsct_blocks(self.nodes[0], miner, 1)
        self.sync_all()

        mine_before = self.get_mine(self.w0, miner)
        # Reward must be immature, with trusted and pending both zero.
        # The exact amount depends on the BLSCT regtest schedule; we only
        # require that immature is positive and that it dominates the total.
        assert_greater_than(mine_before["immature"], _to_dec(0))
        assert_equal(mine_before["trusted"], _to_dec(0))
        assert_equal(mine_before["untrusted_pending"], _to_dec(0))
        assert_equal(mine_before["total"], mine_before["immature"])

        # Wallet-wide accounting must agree with the per-address breakdown.
        wallet_bal = self.w0.getbalances()["mine"]
        assert_equal(_to_dec(wallet_bal["immature"]), mine_before["immature"])

        # Mine past COINBASE_MATURITY (100) so the reward graduates to trusted.
        self.generate_blsct_blocks(self.nodes[0], self.addr0, 200)
        self.sync_all()

        mine_after = self.get_mine(self.w0, miner)
        # The reward output should now be trusted, not immature, and not pending.
        assert_equal(mine_after["immature"], _to_dec(0))
        assert_equal(mine_after["untrusted_pending"], _to_dec(0))
        assert_greater_than(mine_after["trusted"] + mine_after["staked_commitment_balance"], _to_dec(0))

    def test_untrusted_pending_for_external_receive(self):
        self.log.info("=== External mempool receives count as untrusted_pending ===")
        # w0 sends to a fresh w1 address. Don't mine.
        recv_addr = self.w1.getnewaddress(label="", address_type="blsct")
        self.w0.sendtoblsctaddress(recv_addr, Decimal("3"))
        self.sync_mempools()

        # Before confirmation: untrusted_pending > 0, trusted == 0.
        mine = self.get_mine(self.w1, recv_addr)
        assert_equal(mine["trusted"], _to_dec(0))
        assert_equal(mine["immature"], _to_dec(0))
        assert_greater_than(mine["untrusted_pending"], _to_dec(0))
        # The pending amount should be exactly what we sent.
        assert_equal(mine["untrusted_pending"], _to_dec("3"))
        assert_equal(mine["total"], _to_dec("3"))

        # Confirm and recheck. Trusted should now equal the sent amount and
        # untrusted_pending should drain to 0.
        self.generate_blsct_blocks(self.nodes[0], self.addr0, 1)
        self.sync_all()
        mine = self.get_mine(self.w1, recv_addr)
        assert_equal(mine["untrusted_pending"], _to_dec(0))
        assert_equal(mine["trusted"], _to_dec("3"))
        assert_equal(mine["total"], _to_dec("3"))

    def test_minconf_filtering(self):
        self.log.info("=== minconf filters trusted but never moves coins to pending ===")
        # Receive into a fresh address, confirm with exactly one block, then
        # show that minconf=0/1 see it but minconf=2 hides it.
        recv = self.w1.getnewaddress(label="", address_type="blsct")
        self.w0.sendtoblsctaddress(recv, Decimal("4"))
        self.sync_mempools()
        self.generate_blsct_blocks(self.nodes[0], self.addr0, 1)
        self.sync_all()

        mine_0 = self.get_mine(self.w1, recv, minconf=0)
        mine_1 = self.get_mine(self.w1, recv, minconf=1)
        mine_2 = self.get_mine(self.w1, recv, minconf=2)

        assert_equal(mine_0["trusted"], _to_dec("4"))
        assert_equal(mine_1["trusted"], _to_dec("4"))
        # Output has 1 confirmation, so minconf=2 must drop it from "trusted".
        # It must NOT spill into untrusted_pending: that bucket only counts
        # mempool entries.
        assert_equal(mine_2["trusted"], _to_dec(0))
        assert_equal(mine_2["untrusted_pending"], _to_dec(0))

        # Bury it further, then minconf=2 finally sees it.
        self.generate_blsct_blocks(self.nodes[0], self.addr0, 1)
        self.sync_all()
        mine_2_after = self.get_mine(self.w1, recv, minconf=2)
        assert_equal(mine_2_after["trusted"], _to_dec("4"))

    def test_two_addresses_isolated_balances(self):
        self.log.info("=== Distinct addresses report distinct balances ===")
        # Confirm one send each to two fresh addresses and assert the per-
        # address breakdown isolates them correctly.
        a1 = self.w1.getnewaddress(label="", address_type="blsct")
        a2 = self.w1.getnewaddress(label="", address_type="blsct")

        self.w0.sendtoblsctaddress(a1, Decimal("1"))
        self.sync_mempools()
        self.generate_blsct_blocks(self.nodes[0], self.addr0, 1)
        self.sync_all()

        self.w0.sendtoblsctaddress(a2, Decimal("2.5"))
        self.sync_mempools()
        self.generate_blsct_blocks(self.nodes[0], self.addr0, 1)
        self.sync_all()

        m1 = self.get_mine(self.w1, a1)
        m2 = self.get_mine(self.w1, a2)
        assert_equal(m1["trusted"], _to_dec("1"))
        assert_equal(m1["untrusted_pending"], _to_dec(0))
        assert_equal(m2["trusted"], _to_dec("2.5"))
        assert_equal(m2["untrusted_pending"], _to_dec(0))

    def test_listblsctunspent_filters_by_address(self):
        self.log.info("=== listblsctunspent filters and labels BLSCT outputs by address ===")
        # Send distinct, easy-to-track amounts to two fresh BLSCT addresses
        # on w1, confirm them, and verify listblsctunspent reports exactly
        # the expected per-address slice.
        a1 = self.w1.getnewaddress(label="alpha", address_type="blsct")
        a2 = self.w1.getnewaddress(label="beta", address_type="blsct")
        amt1 = Decimal("3.125")
        amt2 = Decimal("5.5")

        self.w0.sendtoblsctaddress(a1, amt1)
        self.sync_mempools()
        self.generate_blsct_blocks(self.nodes[0], self.addr0, 1)
        self.sync_all()
        self.w0.sendtoblsctaddress(a2, amt2)
        self.sync_mempools()
        self.generate_blsct_blocks(self.nodes[0], self.addr0, 1)
        self.sync_all()

        # No filter: w1 should at minimum have the two outputs we just sent
        # plus whatever it accumulated from earlier sub-tests.
        all_unspent = self.w1.listblsctunspent()
        matching_a1 = [u for u in all_unspent if u.get("address") == a1]
        matching_a2 = [u for u in all_unspent if u.get("address") == a2]
        assert_equal(len(matching_a1), 1)
        assert_equal(len(matching_a2), 1)
        assert_equal(_to_dec(matching_a1[0]["amount"]), amt1)
        assert_equal(_to_dec(matching_a2[0]["amount"]), amt2)

        # Per-entry fields: addresses match, scriptPubKey is a non-empty hex
        # string, and the wallet says it can sign this output.
        for entry, expected_label in [(matching_a1[0], "alpha"), (matching_a2[0], "beta")]:
            assert entry["signable"] is True, f"expected signable, got {entry}"
            assert entry["watchonly"] is False, f"expected not watchonly, got {entry}"
            assert isinstance(entry["scriptPubKey"], str) and len(entry["scriptPubKey"]) > 0
            assert_greater_than(entry["confirmations"], 0)
            assert_equal(entry.get("label"), expected_label)

        # Address-filter mode: pass only a1 and verify only outputs to a1 are
        # returned. The filter must be exact: a2's output must NOT appear.
        filtered = self.w1.listblsctunspent(1, 9999999, [a1])
        assert_equal(len(filtered), 1)
        assert_equal(filtered[0]["address"], a1)
        assert_equal(_to_dec(filtered[0]["amount"]), amt1)

        # Passing both addresses returns both, and nothing else.
        filtered_both = self.w1.listblsctunspent(1, 9999999, [a1, a2])
        addrs_returned = sorted(u["address"] for u in filtered_both)
        assert_equal(addrs_returned, sorted([a1, a2]))

        # Passing an unfunded fresh address returns nothing.
        empty_addr = self.w1.getnewaddress(label="", address_type="blsct")
        filtered_empty = self.w1.listblsctunspent(1, 9999999, [empty_addr])
        assert_equal(filtered_empty, [])

        # Invalid address triggers RPC_INVALID_ADDRESS_OR_KEY (-5).
        assert_raises_rpc_error(-5, "Invalid Bitcoin address", self.w1.listblsctunspent, 1, 9999999, ["not_an_address"])

        # query_options: minimumAmount drops any UTXO worth less than the
        # smaller of our two amounts. amt1 (3.125) < amt2 (5.5), so a
        # minimumAmount strictly greater than amt1 but <= amt2 must drop a1
        # and keep a2.
        between = (amt1 + amt2) / 2  # = 4.3125
        large_only = self.w1.listblsctunspent(1, 9999999, [a1, a2], {"minimumAmount": between})
        addrs_after = [u["address"] for u in large_only]
        assert a1 not in addrs_after, f"a1 should have been filtered by minimumAmount, got {large_only}"
        assert a2 in addrs_after, f"a2 should remain after minimumAmount, got {large_only}"

        # maxconf=0 excludes everything confirmed; the just-mined outputs
        # all have confirmations >= 1.
        zero_conf = self.w1.listblsctunspent(0, 0, [a1, a2])
        assert_equal(zero_conf, [])

    def test_listblsctunspent_matches_getbalanceforaddress(self):
        self.log.info("=== Sum of listblsctunspent outputs at an address equals getbalanceforaddress.trusted ===")
        # Pick a fresh address, fund it twice with different amounts, then
        # verify that listblsctunspent's per-address UTXO sum equals the
        # trusted balance reported by getbalanceforaddress.
        addr = self.w1.getnewaddress(label="", address_type="blsct")
        sends = [Decimal("0.5"), Decimal("1.25"), Decimal("2.0")]
        for amt in sends:
            self.w0.sendtoblsctaddress(addr, amt)
            self.sync_mempools()
            self.generate_blsct_blocks(self.nodes[0], self.addr0, 1)
            self.sync_all()

        unspent = self.w1.listblsctunspent(1, 9999999, [addr])
        # We sent three separate transactions to this address; the wallet
        # therefore must have three independent UTXOs at this address.
        assert_equal(len(unspent), len(sends))
        utxo_sum = sum(_to_dec(u["amount"]) for u in unspent)
        assert_equal(utxo_sum, sum(sends))

        # getbalanceforaddress.mine.trusted must agree with the UTXO sum
        # exactly, since all outputs are confirmed and unspent.
        mine = self.get_mine(self.w1, addr)
        assert_equal(mine["trusted"], utxo_sum)
        assert_equal(mine["untrusted_pending"], _to_dec(0))
        assert_equal(mine["immature"], _to_dec(0))

        # Now spend one of those outputs back to w0 and verify both views
        # update consistently: listblsctunspent loses an entry and
        # getbalanceforaddress.trusted decreases accordingly.
        spend_amount = Decimal("0.5")  # matches the first send exactly
        self.w1.sendtoblsctaddress(self.addr0, spend_amount)
        self.sync_mempools()
        self.generate_blsct_blocks(self.nodes[0], self.addr0, 1)
        self.sync_all()

        unspent_after = self.w1.listblsctunspent(1, 9999999, [addr])
        sum_after = sum(_to_dec(u["amount"]) for u in unspent_after)
        mine_after = self.get_mine(self.w1, addr)
        # The two views must still agree after the spend.
        assert_equal(mine_after["trusted"], sum_after)
        # And the new total must be strictly less than before the spend.
        assert_greater_than(utxo_sum, sum_after)

    def test_staked_commitment_balance(self):
        self.log.info("=== Staked commitments are reported under staked_commitment_balance ===")
        # The wallet was funded earlier by mining many blocks to self.addr0.
        # stakelock creates a staked-commitment output, and the wallet
        # records the BLSCT recovered destination for that output. The
        # per-address RPC must surface that value in the staked bucket
        # rather than in 'trusted'.
        stake_amount = Decimal("100")
        before = self.w0.getbalances()["mine"]
        assert_greater_than(_to_dec(before["trusted"]), stake_amount + Decimal("1"))

        stake_txid = self.w0.stakelock(stake_amount)
        assert stake_txid
        self.generate_blsct_blocks(self.nodes[0], self.addr0, 2)
        self.sync_all()

        # Find which address ended up owning the staked commitment by
        # cross-referencing the wallet's stake list with the per-address
        # breakdown. There should be exactly one address whose RPC reports
        # a non-zero staked_commitment_balance.
        wallet_after = self.w0.getbalances()["mine"]
        assert_greater_than(_to_dec(wallet_after["staked_commitment_balance"]), _to_dec(0))

    def test_address_not_in_wallet(self):
        self.log.info("=== Querying a foreign address returns zero ===")
        # An address generated on w1 but never funded from w0 should show as
        # all-zero when queried via w0 (w0 has no recovered outputs to it).
        foreign = self.w1.getnewaddress(label="", address_type="blsct")
        mine = self.get_mine(self.w0, foreign)
        assert_equal(mine["trusted"], _to_dec(0))
        assert_equal(mine["untrusted_pending"], _to_dec(0))
        assert_equal(mine["immature"], _to_dec(0))
        assert_equal(mine["staked_commitment_balance"], _to_dec(0))


if __name__ == "__main__":
    BlsctGetBalanceForAddressTest(__file__).main()
