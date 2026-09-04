#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""RPC-surface coverage for the aggregation bridge.

The node-side pick -> combine -> verify -> evict path is proven end-to-end by
the aggregation_tests unit test (which can build real BLSCT halves via
TxFactory). Here we cover the RPC surface that a wallet / orchestrator uses:
getaggregationhint and getp2pmsgaggregate, including their error paths, on a
node with an empty pool. (Driving a full aggregate from the functional layer
needs the deferred wallet half-build RPCs.)
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class P2PMsgAggregateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-p2pmsg=1", "-p2pmsgpowbits=1"]]

    def run_test(self):
        n = self.nodes[0]

        # Hint reports an empty pool and a positive per-candidate fee.
        hint = n.getaggregationhint()
        assert_equal(hint["enabled"], True)
        assert_equal(hint["available"], 0)
        assert hint["candidate_weight"] > 0
        assert hint["extra_fee_per_candidate"] > 0

        # Aggregating garbage hex is a decode error.
        assert_raises_rpc_error(-22, "TX decode failed", n.getp2pmsgaggregate, "nothex")

        # Injecting garbage hex is a decode error too.
        assert_raises_rpc_error(-22, "TX decode failed", n.addaggregationcandidate, "00")

        self.log.info("aggregation bridge RPC surface OK")


if __name__ == "__main__":
    P2PMsgAggregateTest(__file__).main()
