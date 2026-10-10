#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Aggregates whose input count crosses the CompactSize boundary.

A count of 253 or more serializes in three bytes instead of one. An own half of
252 inputs merged with one pooled cover candidate has 253 inputs, so the
combined tx is two bytes heavier than the own half plus the candidate's body.
The own half must pay for those bytes: under-funding them leaves the aggregate
below the consensus fee floor, the broadcast is rejected, the candidate is
evicted and the wallet falls back to a plain transaction.

Each aggregating wallet path is driven across the boundary: a default
aggregated send, aggregatesend and consolidate.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PULL_ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1", "-candidatepullinterval=2", "-servecandidates=0"]

# One below the CompactSize boundary: one cover input takes the merged count to
# 253, the first count that needs three bytes.
OWN_INPUTS = 252


class P2PMsgAggregateCountBoundaryTest(BitcoinTestFramework):
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

    def serve_candidate(self):
        """Answer one of node0's queued pull requests from w1 and wait for
        node0 to pool the candidate. Returns the candidate's input outpoints."""
        keys = []

        def got_request():
            keys.extend(self.nodes[1].listpendingcandidaterequests())
            return len(keys) > 0

        self.wait_until(got_request, timeout=120)
        before = self.nodes[0].getaggregationhint()["available"]
        inputs = self.w1.replycandidate(keys[0])["inputs"]
        assert inputs, "replycandidate returned no inputs; the merge assertions would be vacuous"
        self.wait_until(lambda: self.nodes[0].getaggregationhint()["available"] > before, timeout=120)
        return inputs

    def assert_merged_across_boundary(self, txid, cand_inputs):
        self.wait_until(lambda: txid in self.nodes[0].getrawmempool(), timeout=60)
        tx = self.nodes[0].getrawtransaction(txid, True)
        prevouts = {vin["outid"] for vin in tx["vin"] if "outid" in vin}
        for outpoint in cand_inputs:
            assert outpoint in prevouts, "fell back to plain: cover input %s missing" % outpoint
        assert_equal(len(tx["vin"]), OWN_INPUTS + len(cand_inputs))
        assert_equal(self.nodes[0].getaggregationhint()["available"], 0)
        self.generatetoblsctaddress(self.nodes[0], 1, self.miner0)
        self.sync_blocks()
        assert txid not in self.nodes[0].getrawmempool(), "boundary aggregate did not confirm"

    def run_test(self):
        n0, n1 = self.nodes
        n0.createwallet(wallet_name="w0", blsct=True, storage_output=True)
        n1.createwallet(wallet_name="w1", blsct=True, storage_output=True)
        w0 = n0.get_wallet_rpc("w0")
        self.w1 = n1.get_wallet_rpc("w1")

        # w1 takes the oversized first-block reward (and serves candidates
        # from it), so every coin w0 mines is one equal block reward.
        self.generatetoblsctaddress(n1, 1, self.w1.getnewaddress(label="", address_type="blsct"))
        self.sync_blocks()
        self.miner0 = w0.getnewaddress(label="", address_type="blsct")
        remaining = 3 * OWN_INPUTS + 110
        while remaining > 0:
            batch = min(50, remaining)
            self.generatetoblsctaddress(n0, batch, self.miner0)
            remaining -= batch
        self.sync_blocks()
        amounts = {Decimal(str(u["amount"])) for u in w0.listblsctunspent()}
        assert_equal(len(amounts), 1)
        reward = amounts.pop()
        # Half a reward past OWN_INPUTS - 1 of them: coin selection needs
        # exactly OWN_INPUTS equal coins to fund it, with change to spare.
        amount = (OWN_INPUTS - 1) * reward + reward / 2
        dest = self.w1.getnewaddress(label="", address_type="blsct")

        cand_inputs = self.serve_candidate()
        w0.sendtoblsctaddress(dest, amount)
        self.wait_until(lambda: len(n0.getrawmempool()) == 1, timeout=60)
        self.assert_merged_across_boundary(n0.getrawmempool()[0], cand_inputs)
        self.log.info("default aggregated send paid for its 3-byte input count")

        cand_inputs = self.serve_candidate()
        res = w0.aggregatesend(dest, amount, 16)
        assert_equal(res["candidates_merged"], 1)
        self.assert_merged_across_boundary(res["txid"], cand_inputs)
        self.log.info("aggregatesend paid for its 3-byte input count")

        cand_inputs = self.serve_candidate()
        txids = w0.consolidate(1, OWN_INPUTS)
        assert_equal(len(txids), 1)
        self.assert_merged_across_boundary(txids[0], cand_inputs)
        self.log.info("consolidate paid for its 3-byte input count")


if __name__ == "__main__":
    P2PMsgAggregateCountBoundaryTest(__file__).main()
