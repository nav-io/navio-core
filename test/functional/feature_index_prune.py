#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test indices in conjunction with prune."""
import os
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class FeatureIndexPruneTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [
            ["-fastprune", "-prune=1", "-blockfilterindex=1"],
            ["-fastprune", "-prune=1", "-coinstatsindex=1"],
            ["-fastprune", "-prune=1", "-blockfilterindex=1", "-coinstatsindex=1"],
            []
        ]

    def sync_index(self, height=None):
        # Every call here waits for the indices to catch up to the chain tip.
        # Deriving the target from the tip (instead of hard-coding it) keeps
        # the test independent of navio's exact block heights.
        if height is None:
            height = self.nodes[0].getblockcount()
        expected_filter = {
            'basic block filter index': {'synced': True, 'best_block_height': height},
        }
        self.wait_until(lambda: self.nodes[0].getindexinfo() == expected_filter)

        expected_stats = {
            'coinstatsindex': {'synced': True, 'best_block_height': height}
        }
        self.wait_until(lambda: self.nodes[1].getindexinfo() == expected_stats)

        expected = {**expected_filter, **expected_stats}
        self.wait_until(lambda: self.nodes[2].getindexinfo() == expected)

    def reconnect_nodes(self):
        self.connect_nodes(0,1)
        self.connect_nodes(0,2)
        self.connect_nodes(0,3)

    def mine_batches(self, blocks):
        n = blocks // 250
        for _ in range(n):
            self.generate(self.nodes[0], 250)
        self.generate(self.nodes[0], blocks % 250)
        self.sync_blocks()

    def restart_without_indices(self):
        for i in range(3):
            self.restart_node(i, extra_args=["-fastprune", "-prune=1"])
        self.reconnect_nodes()

    def run_test(self):
        filter_nodes = [self.nodes[0], self.nodes[2]]
        stats_nodes = [self.nodes[1], self.nodes[2]]

        self.log.info("check if we can access blockfilters and coinstats when pruning is enabled but no blocks are actually pruned")
        self.sync_index()
        tip = self.nodes[0].getbestblockhash()
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(tip)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=tip)['muhash']

        self.mine_batches(500)
        self.sync_index()

        self.log.info("prune some blocks")
        for node in self.nodes[:2]:
            # Match the log message without the trailing height: the exact
            # "limited pruning" height is another block-file-wrap magic number
            # that differs in navio, and the returned pruneheight asserted just
            # below already pins the behaviour.
            with node.assert_debug_log(['limited pruning to height ']):
                pruneheight_new = node.pruneblockchain(400)
                # The prune heights asserted here and below are magic numbers
                # determined by the thresholds at which block files wrap, so
                # they depend on disk serialization and the default block file
                # size. They differ from upstream Bitcoin Core because navio's
                # BLSCT blocks serialize to different sizes.
                assert_equal(pruneheight_new, 228)

        self.log.info("check if we can access the tips blockfilter and coinstats when we have pruned some blocks")
        tip = self.nodes[0].getbestblockhash()
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(tip)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=tip)['muhash']

        self.log.info("check if we can access the blockfilter and coinstats of a pruned block")
        height_hash = self.nodes[0].getblockhash(2)
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(height_hash)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=height_hash)['muhash']

        # mine and sync index up to a height above the pruneblockchain(1000)
        # boundary, so the later prune (with indices disabled) stays at or
        # below the index best block and the index can resume.
        self.generate(self.nodes[0], 301)
        self.sync_index()

        self.restart_without_indices()

        self.log.info("make sure trying to access the indices throws errors")
        for node in filter_nodes:
            msg = "Index is not enabled for filtertype basic"
            assert_raises_rpc_error(-1, msg, node.getblockfilter, height_hash)
        for node in stats_nodes:
            msg = "Querying specific block heights requires coinstatsindex"
            assert_raises_rpc_error(-8, msg, node.gettxoutsetinfo, "muhash", height_hash)

        self.mine_batches(749)

        self.log.info("prune exactly up to the indices best blocks while the indices are disabled")
        for i in range(3):
            pruneheight_2 = self.nodes[i].pruneblockchain(1000)
            assert_equal(pruneheight_2, 918)
            # Restart the nodes again with the indices activated
            self.restart_node(i, extra_args=self.extra_args[i])

        self.log.info("make sure that we can continue with the partially synced indices after having pruned up to the index height")
        self.sync_index()

        self.log.info("prune further than the indices best blocks while the indices are disabled")
        self.restart_without_indices()
        self.mine_batches(1000)

        for i in range(3):
            pruneheight_3 = self.nodes[i].pruneblockchain(2000)
            assert_greater_than(pruneheight_3, pruneheight_2)
            self.stop_node(i)

        self.log.info("make sure we get an init error when starting the nodes again with the indices")
        filter_msg = "Error: basic block filter index best block of the index goes beyond pruned data. Please disable the index or reindex (which will download the whole blockchain again)"
        stats_msg = "Error: coinstatsindex best block of the index goes beyond pruned data. Please disable the index or reindex (which will download the whole blockchain again)"
        end_msg = f"{os.linesep}Error: Failed to start indexes, shutting down.."
        for i, msg in enumerate([filter_msg, stats_msg, filter_msg]):
            self.nodes[i].assert_start_raises_init_error(extra_args=self.extra_args[i], expected_msg=msg+end_msg)

        self.log.info("make sure the nodes start again with the indices and an additional -reindex arg")
        for i in range(3):
            restart_args = self.extra_args[i]+["-reindex"]
            self.restart_node(i, extra_args=restart_args)
            # The nodes need to be reconnected to the non-pruning node upon restart, otherwise they will be stuck
            self.connect_nodes(i, 3)

        self.sync_blocks(timeout=300)
        self.sync_index()

        for node in self.nodes[:2]:
            with node.assert_debug_log(['limited pruning to height ']):
                pruneheight_new = node.pruneblockchain(2500)
                assert_equal(pruneheight_new, 2298)

        self.log.info("ensure that prune locks don't prevent indices from failing in a reorg scenario")
        # Reorg point: a height above the pruned data so the block to
        # invalidate is still available, and below the tip.
        reorg_height = 2480
        tip_height = self.nodes[0].getblockcount()
        with self.nodes[0].assert_debug_log(['basic block filter index prune lock moved back to ']):
            self.nodes[3].invalidateblock(self.nodes[0].getblockhash(reorg_height))
            # node3 (unpruned) must out-mine the other nodes' tip so they reorg
            # onto its branch. Derive the count from the current tip instead of
            # hard-coding it, since navio's block heights differ from upstream.
            self.generate(self.nodes[3], tip_height - reorg_height + 2)
            self.sync_blocks()


if __name__ == '__main__':
    FeatureIndexPruneTest(__file__).main()
