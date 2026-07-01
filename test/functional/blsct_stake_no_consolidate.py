#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the -consolidatestakedcommitments flag.

By default `stakelock` folds a wallet's existing staked commitments into the
new commitment (one consolidated stake). With -consolidatestakedcommitments=0
each `stakelock` produces its own commitment, so a single wallet can hold the
>=2 distinct commitments a PoS membership ring needs, and `stakeunlock` only
consumes the commitments required to cover the requested amount.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlsctStakeNoConsolidateTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=2):
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to_generate, address)
            remaining -= to_generate

    def commitment_amounts(self, wallet):
        """Return the list of staked-commitment amounts (as Decimals)."""
        return [Decimal(c["amount"]) for c in wallet.liststakedcommitments()]

    def run_test(self):
        # blsctregtest minimum stake is 100 NAV.
        self.min_stake = 100
        node = self.nodes[0]

        node.createwallet(wallet_name="w", blsct=True)
        wallet = node.get_wallet_rpc("w")
        addr = wallet.getnewaddress(label="", address_type="blsct")
        self.generate_blsct_blocks(node, addr, 101)
        assert wallet.getbalance() > self.min_stake * 4

        self.log.info("Default: consolidation ON -> stakelocks merge into one commitment")
        wallet.stakelock(self.min_stake)
        self.generate_blsct_blocks(node, addr, 1)
        amounts = self.commitment_amounts(wallet)
        assert_equal(len(amounts), 1)
        assert_equal(amounts[0], Decimal(self.min_stake))

        wallet.stakelock(self.min_stake)
        self.generate_blsct_blocks(node, addr, 1)
        amounts = self.commitment_amounts(wallet)
        # Folded into a single commitment of 2 * min_stake.
        assert_equal(len(amounts), 1)
        assert_equal(amounts[0], Decimal(self.min_stake * 2))

        self.log.info("Restart with -consolidatestakedcommitments=0")
        self.restart_node(0, extra_args=["-consolidatestakedcommitments=0"])
        node.loadwallet("w")
        wallet = node.get_wallet_rpc("w")
        addr = wallet.getnewaddress(label="", address_type="blsct")

        self.log.info("Flag OFF: a new stakelock yields a separate commitment")
        before = self.commitment_amounts(wallet)
        assert_equal(len(before), 1)  # the consolidated 200 from before persists
        wallet.stakelock(self.min_stake)
        self.generate_blsct_blocks(node, addr, 1)
        amounts = sorted(self.commitment_amounts(wallet))
        # Now two distinct commitments: the untouched 200 and a fresh 100.
        assert_equal(len(amounts), 2)
        assert_equal(amounts[0], Decimal(self.min_stake))
        assert_equal(amounts[1], Decimal(self.min_stake * 2))

        self.log.info("A single wallet can now present a ring of >=2 commitments")
        assert len(self.commitment_amounts(wallet)) >= 2

        self.log.info("Flag OFF: stakeunlock consumes only the commitment(s) needed")
        wallet.stakeunlock(self.min_stake)
        self.generate_blsct_blocks(node, addr, 1)
        amounts = sorted(self.commitment_amounts(wallet))
        # The 100 commitment is spent; the 200 stays intact and separate.
        assert_equal(amounts, [Decimal(self.min_stake * 2)])


if __name__ == '__main__':
    BlsctStakeNoConsolidateTest(__file__).main()
