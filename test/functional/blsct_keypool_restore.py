#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Regression test for BLSCT restore/rescan keypool top-up."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlsctKeypoolRestoreTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [["-keypool=3"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=4):
        blocks = []
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            blocks.extend(self.generatetoblsctaddress(node, to_generate, address))
            remaining -= to_generate
        return blocks

    def run_test(self):
        node = self.nodes[0]

        node.createwallet(wallet_name="funder", blsct=True, storage_output=True)
        node.createwallet(wallet_name="origin", blsct=True, storage_output=True)
        funder = node.get_wallet_rpc("funder")
        origin = node.get_wallet_rpc("origin")
        mining_addr = funder.getnewaddress(label="", address_type="blsct")

        self.log.info("Mine funds for the sending wallet")
        self.generate_blsct_blocks(node, mining_addr, 210)

        mnemonic = origin.dumpmnemonic()

        self.log.info("Consume the initial external BLSCT lookahead and step one address beyond it")
        addrs = [origin.getnewaddress(label="", address_type="blsct") for _ in range(4)]
        last_in_pool = addrs[2]
        first_out_of_pool = addrs[3]

        self.log.info("Send to an address just beyond the restored wallet's initial lookahead")
        funder.sendtoblsctaddress(first_out_of_pool, Decimal("1"))
        self.generate_blsct_blocks(node, mining_addr, 1)

        self.log.info("Also send to the last address that still fits in the initial lookahead")
        funder.sendtoblsctaddress(last_in_pool, Decimal("2"))
        self.generate_blsct_blocks(node, mining_addr, 1)

        self.log.info("Restore a second wallet from the same mnemonic and rescan the chain")
        node.createwallet(wallet_name="restore", blsct=True, storage_output=True, mnemonic=mnemonic)
        restore = node.get_wallet_rpc("restore")
        restore.rescanblockchain()
        assert_equal(Decimal(str(restore.getbalanceforaddress(last_in_pool)["mine"]["trusted"])), Decimal("2"))
        assert_equal(Decimal(str(restore.getbalanceforaddress(first_out_of_pool)["mine"]["trusted"])), Decimal("1"))
        assert_equal(Decimal(str(restore.getblsctbalance())), Decimal("3"))


if __name__ == "__main__":
    BlsctKeypoolRestoreTest(__file__).main()
