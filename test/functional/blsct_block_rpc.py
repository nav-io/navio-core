#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Exercise block RPC fee reporting for BLSCT transactions."""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BLSCTBlockRPCTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
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
        node = self.nodes[0]
        node.createwallet(wallet_name="wallet", blsct=True)
        wallet = node.get_wallet_rpc("wallet")

        funding_address = wallet.getnewaddress(label="", address_type="blsct")
        recipient_address = wallet.getnewaddress(label="", address_type="blsct")

        self.generate_blsct_blocks(node, funding_address, 101)

        raw_tx = wallet.createblsctrawtransaction(
            [],
            [{"address": recipient_address, "amount": 10_000_000, "memo": "block rpc regression"}],
        )
        funded_tx = wallet.fundblsctrawtransaction(raw_tx)
        decoded_funded = wallet.decodeblsctrawtransaction(funded_tx)
        expected_fee = Decimal(decoded_funded["fee"]) / COIN

        signed_tx = wallet.signblsctrawtransaction(funded_tx)
        txid = node.sendrawtransaction(signed_tx)
        blockhash = self.generate_blsct_blocks(node, funding_address, 1)[0]

        for verbosity in (2, 3):
            block = node.getblock(blockhash, verbosity)
            tx = block["tx"][1]
            assert_equal(tx["txid"], txid)
            assert_equal(tx["fee"], expected_fee)

        stats = node.getblockstats(blockhash, ["totalfee", "avgfee", "minfee", "maxfee"])
        assert_equal(stats["totalfee"], expected_fee)
        assert_equal(stats["avgfee"], expected_fee)
        assert_equal(stats["minfee"], expected_fee)
        assert_equal(stats["maxfee"], expected_fee)


if __name__ == "__main__":
    BLSCTBlockRPCTest().main()
