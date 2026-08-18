#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end test of the pull-based aggregation candidate flow.

Node0's background puller broadcasts AGG_ANN requests (fresh reply key per
round). Node1 queues them; the wallet answers one with replycandidate, which
builds a fee-0 self-spend cover candidate (no fee output) and sends it as a
CANDIDATE_TX encrypted 1:1 to node0's reply key. Node0 pools it. The candidate
is only valid inside a CombineHalves aggregate, so it must NOT be accepted to
the mempool on its own.
"""

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework

# Fast pull cadence so the test does not wait a minute per round.
PULL_ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1", "-candidatepullinterval=2"]


class P2PMsgCandidateTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [PULL_ARGS, PULL_ARGS]

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

    def claim_request(self, node):
        """Poll until the node has queued a pull request; claim and return one key."""
        keys = []

        def got_one():
            keys.extend(node.listpendingcandidaterequests())
            return len(keys) > 0

        self.wait_until(got_one, timeout=30)
        return keys[0]

    def run_test(self):
        n0, n1 = self.nodes
        n1.createwallet(wallet_name="w1", blsct=True, storage_output=True)
        w1 = n1.get_wallet_rpc("w1")
        miner = w1.getnewaddress(label="", address_type="blsct")

        self.generate_blsct_blocks(n1, miner, 110)
        self.sync_blocks()
        assert Decimal(str(w1.getbalances()["mine"]["trusted"])) > 0

        # Node0's puller floods AGG_ANN rounds; node1 queues the reply keys.
        reply_key = self.claim_request(n1)
        self.log.info("claimed pull request reply key %s..." % reply_key[:16])

        # The wallet answers 1:1 to the reply key; node0 pools the candidate.
        res = w1.replycandidate(reply_key)
        assert "candidate_txid" in res, res
        self.wait_until(lambda: n0.getaggregationhint()["available"] >= 1, timeout=30)
        self.log.info("candidate served and pooled by the requester")

        # The candidate pays no fee, so it must NOT stand alone in the mempool.
        assert res["candidate_txid"] not in n0.getrawmempool(), \
            "fee-0 candidate must not be accepted standalone"
        assert res["candidate_txid"] not in n1.getrawmempool(), \
            "fee-0 candidate must not be accepted standalone"

        # The producer never pools its own served candidate (it was encrypted
        # to node0's key, and producers reject non-session CANDIDATE_TX).
        assert n1.getaggregationhint()["available"] == 0

        self.log.info("pull-based candidate flow OK")


if __name__ == "__main__":
    P2PMsgCandidateTest(__file__).main()
