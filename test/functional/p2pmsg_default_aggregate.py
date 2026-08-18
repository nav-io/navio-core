#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Default-on aggregation of plain wallet sends (-aggregatesends), pull flow.

Two connected p2pmsg nodes with fast background pull rounds. Node0's puller
solicits candidates via AGG_ANN; node1's wallet serves one 1:1-encrypted to
node0's reply key (replycandidate). A PLAIN sendtoblsctaddress on node0 must
then merge the pooled candidate by default: the broadcast tx spends the
candidate's input alongside the wallet's own, and the candidate is evicted
from the pool. Node1 runs with -aggregatesends=0 and must NOT consume its
pooled candidates on a plain send.
"""

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PULL_ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1", "-candidatepullinterval=2"]


class P2PMsgDefaultAggregateTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [
            PULL_ARGS,
            PULL_ARGS + ["-aggregatesends=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=4):
        remaining = num_blocks
        while remaining > 0:
            to = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to, address)
            remaining -= to

    def serve_candidate(self, requester_node, producer_node, producer_wallet):
        """Claim one of requester's queued pull requests on the producer and
        answer it, then wait for the requester to pool the candidate."""
        keys = []

        def got_one():
            keys.extend(producer_node.listpendingcandidaterequests())
            return len(keys) > 0

        self.wait_until(got_one, timeout=30)
        before = requester_node.getaggregationhint()["available"]
        producer_wallet.replycandidate(keys[0])
        self.wait_until(lambda: requester_node.getaggregationhint()["available"] > before, timeout=30)

    def run_test(self):
        n0, n1 = self.nodes
        n0.createwallet(wallet_name="w0", blsct=True, storage_output=True)
        n1.createwallet(wallet_name="w1", blsct=True, storage_output=True)
        w0 = n0.get_wallet_rpc("w0")
        w1 = n1.get_wallet_rpc("w1")
        miner0 = w0.getnewaddress(label="", address_type="blsct")
        miner1 = w1.getnewaddress(label="", address_type="blsct")

        # Fund both wallets past coinbase maturity.
        self.generate_blsct_blocks(n0, miner0, 110)
        self.sync_blocks()
        self.generate_blsct_blocks(n1, miner1, 110)
        self.sync_blocks()
        assert Decimal(str(w0.getbalances()["mine"]["trusted"])) > 0
        assert Decimal(str(w1.getbalances()["mine"]["trusted"])) > 0

        # --- Node1 serves node0's pull request; node0 pools the candidate. ---
        self.serve_candidate(n0, n1, w1)

        # --- A PLAIN send on node0 merges by default. ---
        dest = w1.getnewaddress(label="", address_type="blsct")
        w0.sendtoblsctaddress(dest, 1.0)
        self.wait_until(lambda: len(n0.getrawmempool()) == 1, timeout=20)
        txid = n0.getrawmempool()[0]
        tx = n0.getrawtransaction(txid, True)
        # Own half (>=1 input) + merged candidate (1 input each).
        assert len(tx["vin"]) >= 2, "plain send did not merge the pooled candidate: %r" % tx["vin"]
        # Every picked candidate was evicted from the pool.
        assert_equal(n0.getaggregationhint()["available"], 0)

        # Confirm and check the recipient got paid despite the merge.
        recv_before = Decimal(str(w1.getbalances()["mine"]["trusted"]))
        self.generatetoblsctaddress(n0, 1, miner0)
        self.sync_blocks()
        assert txid not in n0.getrawmempool(), "aggregated send did not confirm"
        self.wait_until(
            lambda: Decimal(str(w1.getbalances()["mine"]["trusted"])) >= recv_before + Decimal("1.0") - Decimal("0.1"),
            timeout=30)
        self.log.info("default-aggregated plain send confirmed")

        # --- Node1 opted out (-aggregatesends=0): its pooled candidates stay. ---
        self.serve_candidate(n1, n0, w0)
        before = n1.getaggregationhint()["available"]
        assert before >= 1
        w1.sendtoblsctaddress(w0.getnewaddress(label="", address_type="blsct"), 1.0)
        self.wait_until(lambda: len(n1.getrawmempool()) >= 1, timeout=20)
        assert_equal(n1.getaggregationhint()["available"], before)
        self.generatetoblsctaddress(n1, 1, miner1)
        self.sync_blocks()
        self.log.info("opt-out plain send left the pool untouched")


if __name__ == "__main__":
    P2PMsgDefaultAggregateTest(__file__).main()
