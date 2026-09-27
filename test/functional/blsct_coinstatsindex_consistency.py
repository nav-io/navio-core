#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test that UTXO-set commitments agree on a BLSCT chain.

A BLSCT output is created from the full block output (range proof included)
but is spent, and restored on a disconnect, from block-undo data that carries
it without the range-proof body. Coins are hashed in one canonical form, so:

- the coinstatsindex muhash, maintained incrementally from blocks and undo
  data, equals the muhash computed from the live UTXO set, and
- hash_serialized_3 and muhash of the live UTXO set do not depend on whether
  the node went through a disconnect/reconnect of the spending blocks.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BLSCTCoinStatsIndexConsistencyTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [["-coinstatsindex"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def sync_index(self, node):
        height = node.getblockcount()
        self.wait_until(lambda: node.getindexinfo("coinstatsindex")["coinstatsindex"] == {
            "synced": True, "best_block_height": height})

    def check_index_matches_utxo_set(self, node):
        """The index muhash equals the one computed from the UTXO set."""
        self.sync_index(node)
        indexed = node.gettxoutsetinfo(hash_type="muhash", use_index=True)
        live = node.gettxoutsetinfo(hash_type="muhash", use_index=False)
        assert_equal(indexed["height"], live["height"])
        assert_equal(indexed["bestblock"], live["bestblock"])
        assert_equal(indexed["txouts"], live["txouts"])
        assert_equal(indexed["bogosize"], live["bogosize"])
        assert_equal(indexed["muhash"], live["muhash"])
        return live["muhash"]

    def utxo_set_hashes(self, node):
        return (node.gettxoutsetinfo(hash_type="hash_serialized_3")["hash_serialized_3"],
                node.gettxoutsetinfo(hash_type="muhash", use_index=False)["muhash"])

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="wallet", blsct=True)
        wallet = node.get_wallet_rpc("wallet")
        address = wallet.getnewaddress(label="", address_type="blsct")

        self.log.info("Mine mature BLSCT coinbase outputs")
        self.generatetoblsctaddress(node, 101, address)
        self.check_index_matches_utxo_set(node)

        self.log.info("Spend BLSCT outputs in two blocks")
        spend_blocks = []
        for _ in range(2):
            for _ in range(2):
                wallet.sendtoblsctaddress(address, Decimal("1"))
            spend_blocks += self.generatetoblsctaddress(node, 1, address)
            block = node.getblock(spend_blocks[-1])
            assert len(block["tx"]) > 1, "spending block must include the sends"
        self.generatetoblsctaddress(node, 1, address)

        self.log.info("Index muhash matches the UTXO set after BLSCT spends")
        muhash_before = self.check_index_matches_utxo_set(node)
        hashes_before = self.utxo_set_hashes(node)
        assert_equal(hashes_before[1], muhash_before)
        tip_before = node.getbestblockhash()

        self.log.info("Disconnect the spending blocks; restored coins hash like the originals")
        node.invalidateblock(spend_blocks[0])
        assert_equal(node.getblockcount(), 101)
        # Every coin restored by the disconnect is in the UTXO set again, so
        # the set equals the one the index recorded at height 101 before any
        # spend.
        assert_equal(self.utxo_set_hashes(node)[1],
                     node.gettxoutsetinfo(hash_type="muhash", hash_or_height=101, use_index=True)["muhash"])

        self.log.info("Mine a competing branch; the index rewinds over BLSCT spends")
        self.generatetoblsctaddress(node, 1, address)
        self.check_index_matches_utxo_set(node)
        for _ in range(2):
            wallet.sendtoblsctaddress(address, Decimal("1"))
        fork_block = self.generatetoblsctaddress(node, 1, address)[0]
        assert len(node.getblock(fork_block)["tx"]) > 1, "fork block must include the sends"
        assert_equal(node.getblockcount(), 103)
        self.check_index_matches_utxo_set(node)

        self.log.info("Reconnect; UTXO-set hashes equal those before the reorg")
        node.reconsiderblock(spend_blocks[0])
        assert_equal(node.getbestblockhash(), tip_before)
        assert_equal(self.check_index_matches_utxo_set(node), muhash_before)
        assert_equal(self.utxo_set_hashes(node), hashes_before)

        self.log.info("Index state survives a restart without a rebuild")
        with node.assert_debug_log(expected_msgs=[], unexpected_msgs=["rebuilding"]):
            self.restart_node(0)
        assert_equal(self.check_index_matches_utxo_set(node), muhash_before)


if __name__ == "__main__":
    BLSCTCoinStatsIndexConsistencyTest(__file__).main()
