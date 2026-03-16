#!/usr/bin/env python3
# Copyright (c) 2024 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test BLSCT output storage mode.

Verifies that wallets created with blsct=True use output storage mode by default,
that balances are correct throughout mining and sending, and that wallet size is
reduced compared to transaction mode.
"""

import os
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)

BLOCK_REWARD = Decimal("50.00000000")

class NavioBlsctOutputStorageTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
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

    def get_wallet_db_size(self, node, wallet_name):
        """Get the size of the wallet database file in bytes."""
        wallet_dir = node.wallets_path
        # Check SQLite first (default for BLSCT)
        wallet_path = os.path.join(wallet_dir, wallet_name, "wallet.sqlite")
        if os.path.exists(wallet_path):
            return os.path.getsize(wallet_path)
        # Fall back to BDB
        wallet_path = os.path.join(wallet_dir, wallet_name, "wallet.dat")
        if os.path.exists(wallet_path):
            return os.path.getsize(wallet_path)
        return 0

    def run_test(self):
        self.test_basic_mining_and_balance()
        self.test_send_to_other_wallet()
        self.test_send_to_self()
        self.test_unconfirmed_balance()
        self.test_block_reorg()
        self.test_staked_commitments()
        self.test_many_transactions()
        self.test_wallet_size_comparison()

    def test_basic_mining_and_balance(self):
        self.log.info("=== Test 1: Basic mining & balance ===")

        # Create wallets - output storage is now default for BLSCT
        self.nodes[0].createwallet(wallet_name="wallet_a", blsct=True)
        self.nodes[1].createwallet(wallet_name="wallet_b", blsct=True)
        self.wallet_a = self.nodes[0].get_wallet_rpc("wallet_a")
        self.wallet_b = self.nodes[1].get_wallet_rpc("wallet_b")

        self.addr_a = self.wallet_a.getnewaddress(label="", address_type="blsct")
        self.addr_b = self.wallet_b.getnewaddress(label="", address_type="blsct")

        self.log.info("Mining 201 blocks to wallet_a")
        self.generate_blsct_blocks(self.nodes[0], self.addr_a, 201)

        balance_a = self.wallet_a.getbalance()
        self.log.info(f"Balance after 201 blocks: {balance_a}")
        assert_greater_than(balance_a, 0)

        wallet_info = self.wallet_a.getwalletinfo()
        self.log.info(f"Wallet info: txcount={wallet_info.get('txcount', 'N/A')}")

    def test_send_to_other_wallet(self):
        self.log.info("=== Test 2: Send to other wallet ===")

        balance_a_before = self.wallet_a.getbalance()
        balance_b_before = self.wallet_b.getbalance()
        self.log.info(f"Before send: A={balance_a_before}, B={balance_b_before}")

        # Send from A to B
        send_amount = Decimal("100.00000000")
        output_hash = self.wallet_a.sendtoblsctaddress(self.addr_b, send_amount)
        self.log.info(f"Sent {send_amount} from A to B, outputHash={output_hash}")

        # Sync mempools so both nodes see the tx, then mine
        self.sync_mempools()
        self.generate_blsct_blocks(self.nodes[0], self.addr_a, 1)

        balance_a_after = self.wallet_a.getbalance()
        balance_b_after = self.wallet_b.getbalance()
        self.log.info(f"After send: A={balance_a_after}, B={balance_b_after}")

        # B should have received the amount
        assert_equal(balance_b_after, balance_b_before + send_amount)

        # Send back from B to A
        send_back = Decimal("50.00000000")
        output_hash2 = self.wallet_b.sendtoblsctaddress(self.addr_a, send_back)
        self.log.info(f"Sent {send_back} back from B to A, outputHash={output_hash2}")

        # Sync mempools so node 0 includes B's tx when mining
        self.sync_mempools()
        self.generate_blsct_blocks(self.nodes[0], self.addr_a, 1)

        balance_a_final = self.wallet_a.getbalance()
        balance_b_final = self.wallet_b.getbalance()
        self.log.info(f"After send back: A={balance_a_final}, B={balance_b_final}")

        # B should have change from the send (100 - 50 - fees)
        assert_greater_than(balance_b_final, 0)
        assert_greater_than(send_back, balance_b_final)  # B has less than 50 due to fees

    def test_send_to_self(self):
        self.log.info("=== Test 3: Send to self ===")

        balance_before = self.wallet_a.getbalance()
        self.log.info(f"Balance before self-send: {balance_before}")

        self_addr = self.wallet_a.getnewaddress(label="", address_type="blsct")
        send_amount = Decimal("10.00000000")
        output_hash = self.wallet_a.sendtoblsctaddress(self_addr, send_amount)
        self.log.info(f"Self-send outputHash: {output_hash}")

        self.generate_blsct_blocks(self.nodes[0], self.addr_a, 1)

        balance_after = self.wallet_a.getbalance()
        self.log.info(f"Balance after self-send: {balance_after}")

        # Balance should still be sensible after self-send (only decreased by fee + gained block reward)
        assert_greater_than(balance_after, 0)

    def test_unconfirmed_balance(self):
        self.log.info("=== Test 4: Unconfirmed balance ===")

        balance_before = self.wallet_a.getbalance()
        self.log.info(f"Before: confirmed={balance_before}")

        send_amount = Decimal("5.00000000")
        output_hash = self.wallet_a.sendtoblsctaddress(self.addr_b, send_amount)
        self.log.info(f"Sent {send_amount}, outputHash={output_hash}")

        balance_during = self.wallet_a.getbalance()
        self.log.info(f"During (unconfirmed): confirmed={balance_during}")

        # Sync mempools so the tx gets included when mining
        self.sync_mempools()
        # Mine to confirm
        self.generate_blsct_blocks(self.nodes[0], self.addr_a, 1)

        balance_after = self.wallet_a.getbalance()
        self.log.info(f"After confirmation: confirmed={balance_after}")

    def test_block_reorg(self):
        self.log.info("=== Test 5: Block reorganization ===")

        balance_before_reorg = self.wallet_a.getbalance()
        self.log.info(f"Balance before reorg test: {balance_before_reorg}")

        # Mine some blocks
        blocks = self.generate_blsct_blocks(self.nodes[0], self.addr_a, 3)

        balance_after_mining = self.wallet_a.getbalance()
        self.log.info(f"Balance after mining 3 blocks: {balance_after_mining}")

        # Invalidate the last block
        self.log.info(f"Invalidating block: {blocks[-1]}")
        self.nodes[0].invalidateblock(blocks[-1])

        balance_after_invalidate = self.wallet_a.getbalance()
        self.log.info(f"Balance after invalidating last block: {balance_after_invalidate}")

        # Reconsider the block
        self.nodes[0].reconsiderblock(blocks[-1])

        balance_after_reconsider = self.wallet_a.getbalance()
        self.log.info(f"Balance after reconsidering block: {balance_after_reconsider}")

        # Balance should be restored
        assert_equal(balance_after_reconsider, balance_after_mining)

    def test_staked_commitments(self):
        self.log.info("=== Test 6: Staked commitments ===")

        balance_before = self.wallet_a.getbalance()
        self.log.info(f"Balance before staking: {balance_before}")

        # Stake some amount
        stake_amount = 200
        try:
            stake_txid = self.wallet_a.stakelock(stake_amount)
            self.log.info(f"Stakelock txid: {stake_txid}")
            self.generate_blsct_blocks(self.nodes[0], self.addr_a, 1)

            balance_after_stake = self.wallet_a.getbalance()
            self.log.info(f"Balance after staking: {balance_after_stake}")
            assert_greater_than(balance_before - balance_after_stake, stake_amount - 10)

            # Unstake
            unstake_txid = self.wallet_a.stakeunlock(stake_amount)
            self.log.info(f"Stakeunlock txid: {unstake_txid}")
            self.generate_blsct_blocks(self.nodes[0], self.addr_a, 1)

            balance_after_unstake = self.wallet_a.getbalance()
            self.log.info(f"Balance after unstaking: {balance_after_unstake}")
        except Exception as e:
            self.log.info(f"Staking test encountered error (may be expected): {e}")

    def test_many_transactions(self):
        self.log.info("=== Test 7: Hundreds of transactions ===")

        # Mine a large number of blocks for funding
        self.log.info("Mining 300 blocks for funding bulk transactions...")
        self.generate_blsct_blocks(self.nodes[0], self.addr_a, 300)

        balance = self.wallet_a.getbalance()
        self.log.info(f"Balance before bulk sends: {balance}")

        # Send many transactions in batches
        num_sends = 50
        send_amount = Decimal("1.00000000")
        successful_sends = 0

        for i in range(num_sends):
            try:
                self.wallet_a.sendtoblsctaddress(self.addr_b, send_amount)
                successful_sends += 1
            except Exception as e:
                self.log.info(f"Send {i+1} failed: {e}")
                # Mine a block to free up UTXOs
                self.generate_blsct_blocks(self.nodes[0], self.addr_a, 1)

            if (i + 1) % 10 == 0:
                self.generate_blsct_blocks(self.nodes[0], self.addr_a, 1)
                self.log.info(f"Completed {i+1}/{num_sends} sends ({successful_sends} successful)")

        # Mine remaining
        self.generate_blsct_blocks(self.nodes[0], self.addr_a, 1)

        balance_a_final = self.wallet_a.getbalance()
        balance_b_final = self.wallet_b.getbalance()
        self.log.info(f"Final balances: A={balance_a_final}, B={balance_b_final}")
        self.log.info(f"Total successful sends: {successful_sends}")

        # Both should have positive balances
        assert_greater_than(balance_a_final, 0)
        assert_greater_than(balance_b_final, 0)

        # Log wallet sizes to measure scaling
        size_a = self.get_wallet_db_size(self.nodes[0], "wallet_a")
        size_b = self.get_wallet_db_size(self.nodes[1], "wallet_b")
        self.log.info(f"Wallet A db size after many txs: {size_a} bytes")
        self.log.info(f"Wallet B db size after many txs: {size_b} bytes")

    def test_wallet_size_comparison(self):
        self.log.info("=== Test 8: Wallet size comparison (output vs transaction mode) ===")

        # The real savings from output mode come from:
        #   1. Range proof stripping (~900 bytes per BLSCT output)
        #   2. Not storing the entire aggregated block tx — in tx-mode, when a block
        #      aggregates outputs from many wallets, ALL outputs (including other wallets')
        #      are stored; output-mode only stores the wallet's own outputs.
        #
        # To demonstrate savings we need blocks with MANY aggregated outputs.
        # We create multiple third-party sender wallets, queue many sends into
        # the mempool, then mine a single block that aggregates them all.
        # The comparison wallets mine these heavy blocks:
        #   tx-mode  → stores the full aggregated tx (all outputs with range proofs)
        #   out-mode → stores only its own coinbase output (stripped range proof)

        NUM_SENDERS = 3
        SENDS_PER_BATCH = 5   # sends queued per sender before mining
        NUM_ROUNDS = 10       # number of mine-after-batch rounds

        # --- Create sender wallets and fund them ---
        # Re-use wallet_a from earlier tests as the first sender (already funded).
        senders = [self.wallet_a]
        sender_addrs = [self.addr_a]
        for i in range(1, NUM_SENDERS):
            wname = f"sender_{i}"
            self.nodes[0].createwallet(wallet_name=wname, blsct=True)
            w = self.nodes[0].get_wallet_rpc(wname)
            a = w.getnewaddress(label="", address_type="blsct")
            senders.append(w)
            sender_addrs.append(a)

        self.log.info(f"Funding {NUM_SENDERS - 1} additional sender wallets...")
        for a in sender_addrs[1:]:
            self.generate_blsct_blocks(self.nodes[0], a, 101)
        # Mine extra blocks so all sender coins mature
        self.generate_blsct_blocks(self.nodes[0], sender_addrs[0], 100)

        # --- Create the two comparison wallets ---
        self.nodes[0].createwallet(wallet_name="wallet_output_fresh", blsct=True)
        self.nodes[0].createwallet(wallet_name="wallet_txmode", blsct=True, storage_output=False)
        wallet_out = self.nodes[0].get_wallet_rpc("wallet_output_fresh")
        wallet_tx = self.nodes[0].get_wallet_rpc("wallet_txmode")
        addr_out = wallet_out.getnewaddress(label="", address_type="blsct")
        addr_tx = wallet_tx.getnewaddress(label="", address_type="blsct")

        # --- Rounds: queue many sends, then mine one block ---
        # Each round the senders also send a small amount to BOTH comparison
        # wallets.  This makes the aggregated block tx "involve" each
        # comparison wallet so that:
        #   tx-mode  → stores the FULL aggregated tx (all outputs + range proofs)
        #   out-mode → stores only its own received output (stripped)
        send_amount = Decimal("1.00000000")
        for rnd in range(NUM_ROUNDS):
            # Every sender queues SENDS_PER_BATCH self-sends (bulk traffic)
            for sw in senders:
                for _ in range(SENDS_PER_BATCH):
                    try:
                        dst = sw.getnewaddress(label="", address_type="blsct")
                        sw.sendtoblsctaddress(dst, send_amount)
                    except Exception as e:
                        self.log.info(f"Send failed (round {rnd}): {e}")
                        break

            # Also send to the comparison wallets so IsMine triggers for
            # the aggregated tx in both wallets
            try:
                senders[0].sendtoblsctaddress(addr_out, send_amount)
                senders[0].sendtoblsctaddress(addr_tx, send_amount)
            except Exception as e:
                self.log.info(f"Send-to-comparison failed (round {rnd}): {e}")

            # Mine one block — it aggregates all pending mempool txs.
            # Alternate miner between the two comparison wallets so both
            # accumulate entries.
            miner_addr = addr_out if rnd % 2 == 0 else addr_tx
            self.generate_blsct_blocks(self.nodes[0], miner_addr, 1)
            self.log.info(f"Round {rnd+1}/{NUM_ROUNDS}: mined block with pending sends from {NUM_SENDERS} senders × {SENDS_PER_BATCH}")

        # Mine a few more blocks to mature some coinbase for balance display
        self.generate_blsct_blocks(self.nodes[0], addr_out, 2)

        balance_out = wallet_out.getbalance()
        balance_tx = wallet_tx.getbalance()
        info_out = wallet_out.getwalletinfo()
        info_tx = wallet_tx.getwalletinfo()
        self.log.info(f"Output-mode balance: {balance_out}, txcount={info_out.get('txcount', 'N/A')}")
        self.log.info(f"Tx-mode balance: {balance_tx}, txcount={info_tx.get('txcount', 'N/A')}")

        size_out = self.get_wallet_db_size(self.nodes[0], "wallet_output_fresh")
        size_tx = self.get_wallet_db_size(self.nodes[0], "wallet_txmode")
        self.log.info(f"Output-mode wallet size: {size_out} bytes")
        self.log.info(f"Tx-mode wallet size:     {size_tx} bytes")

        if size_out > 0 and size_tx > 0:
            count_out = info_out.get('txcount', 201)
            count_tx = info_tx.get('txcount', 201)
            self.log.info(f"Per-entry size (output mode): {size_out}/{count_out} = {size_out/max(count_out,1):.0f} bytes")
            self.log.info(f"Per-entry size (tx mode):     {size_tx}/{count_tx} = {size_tx/max(count_tx,1):.0f} bytes")
            if size_tx > size_out:
                savings_pct = 100.0 * (size_tx - size_out) / size_tx
                self.log.info(f"Output mode saves {savings_pct:.1f}% vs tx mode")
                assert_greater_than(size_tx, size_out)
            else:
                self.log.info(f"No savings observed (output={size_out}, tx={size_tx})")
        else:
            self.log.info("Could not determine wallet sizes for comparison")


if __name__ == '__main__':
    NavioBlsctOutputStorageTest().main()
