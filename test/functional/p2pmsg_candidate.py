#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end test of the pull-based aggregation candidate flow.

Built-in path: node0's background puller broadcasts AGG_ANN requests; node1
(loaded BLSCT wallet, -servecandidates default on) queues them and its
serving thread answers automatically with fee-0 self-spend candidates
encrypted 1:1 to node0's reply keys. Node0 pools them without any RPC
orchestration and no navio-p2pmsg daemon.

Manual path: with auto-serving off, a queued request is claimed one-shot via
listpendingcandidaterequests and answered via replycandidate.
"""

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework

# Fast pull/serve cadence so the test does not wait a minute per round.
FAST = ["-p2pmsg=1", "-p2pmsgpowbits=1", "-candidatepullinterval=2", "-servecandidateinterval=2"]


class P2PMsgCandidateTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        # node0: requester (no wallet). node1: producer, auto-serving ON.
        self.extra_args = [FAST, FAST]

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

    def run_test(self):
        n0, n1 = self.nodes
        n1.createwallet(wallet_name="w1", blsct=True, storage_output=True)
        w1 = n1.get_wallet_rpc("w1")
        miner = w1.getnewaddress(label="", address_type="blsct")

        self.generate_blsct_blocks(n1, miner, 110)
        self.sync_blocks()
        assert Decimal(str(w1.getbalances()["mine"]["trusted"])) > 0

        # --- Built-in serving: node0's pool fills with NO orchestration. ---
        self.wait_until(lambda: n0.getaggregationhint()["available"] >= 1, timeout=180)
        self.log.info("built-in serving filled the requester's pool automatically")

        # Producer never pools its own served candidates (they were encrypted
        # to node0's keys, and nodes reject non-session CANDIDATE_TX). Its own
        # pulls go unserved: node0 has no wallet.
        assert n1.getaggregationhint()["available"] == 0

        # Fee-0 candidates must never stand alone in a mempool.
        assert n0.getrawmempool() == []
        assert n1.getrawmempool() == []

        # --- Manual serving path (daemon flow): claim + replycandidate. ---
        self.restart_node(1, extra_args=FAST + ["-servecandidates=0"])
        self.connect_nodes(0, 1)
        n1.loadwallet("w1")
        w1 = n1.get_wallet_rpc("w1")
        keys = []

        def got_one():
            keys.extend(n1.listpendingcandidaterequests())
            return len(keys) > 0

        def got_two():
            keys.extend(n1.listpendingcandidaterequests())
            return len(set(keys)) >= 2

        self.wait_until(got_two, timeout=180)
        uniq = list(dict.fromkeys(keys))
        before = n0.getaggregationhint()["available"]
        res = w1.replycandidate(uniq[0])
        assert "candidate_txid" in res, res
        self.wait_until(lambda: n0.getaggregationhint()["available"] > before, timeout=120)
        assert res["candidate_txid"] not in n0.getrawmempool()
        self.log.info("manual claim + replycandidate served OK")

        # Reservation ledger: a second candidate served while the first is
        # still live must spend a DISTINCT coin (this is the point of the
        # per-input reservation; without it every candidate reuses the same
        # first coin and requesters' input-deduped pools reject the rest).
        res2 = w1.replycandidate(uniq[1])
        assert res2["candidate_txid"] != res["candidate_txid"]
        assert set(res["inputs"]).isdisjoint(set(res2["inputs"])), (
            "second candidate reused a reserved coin: %r vs %r" % (res["inputs"], res2["inputs"]))
        self.log.info("two live candidates spend distinct coins")


if __name__ == "__main__":
    P2PMsgCandidateTest(__file__).main()
