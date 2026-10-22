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

# Auto-serving is disabled on both nodes: this test's assertions on exact pool
# counts (evicted-to-zero after a merge, untouched on opt-out) need candidates
# served only at the moments the test chooses. The built-in server is covered
# by p2pmsg_candidate.py.
PULL_ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1", "-candidatepullinterval=2", "-servecandidates=0"]


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

        # 120s (was 30): serve/propagation-dependent, flakes under the
        # [commits] job's full-suite saturation; CentOS excludes this test.
        self.wait_until(got_one, timeout=120)
        before = requester_node.getaggregationhint()["available"]
        reply = producer_wallet.replycandidate(keys[0])
        self.wait_until(lambda: requester_node.getaggregationhint()["available"] > before, timeout=120)
        return reply["inputs"]

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
        cand_inputs = self.serve_candidate(n0, n1, w1)

        # --- A PLAIN send on node0 merges by default. ---
        dest = w1.getnewaddress(label="", address_type="blsct")
        w0.sendtoblsctaddress(dest, 1.0)
        self.wait_until(lambda: len(n0.getrawmempool()) == 1, timeout=60)
        txid = n0.getrawmempool()[0]
        tx = n0.getrawtransaction(txid, True)
        # Own half (>=1 input) + merged candidate (1 input each).
        assert len(tx["vin"]) >= 2, "plain send did not merge the pooled candidate: %r" % tx["vin"]
        # The candidate's exact input outpoints appear in the broadcast tx.
        # (available == 0 alone also holds on the fallback path -- eviction
        # runs win or lose -- so it cannot distinguish a merge from a plain
        # send; the outpoints can.)
        broadcast_prevouts = {vin["outid"] for vin in tx["vin"] if "outid" in vin}
        assert cand_inputs, "replycandidate returned no inputs; the outpoint assertion below would be vacuous"
        for outpoint in cand_inputs:
            assert outpoint in broadcast_prevouts, (
                "candidate input %s missing from broadcast tx inputs %r" % (outpoint, sorted(broadcast_prevouts)))
        # Every picked candidate was evicted from the pool.
        assert_equal(n0.getaggregationhint()["available"], 0)

        # Confirm and check the recipient got paid despite the merge.
        recv_before = Decimal(str(w1.getbalances()["mine"]["trusted"]))
        self.generatetoblsctaddress(n0, 1, miner0)
        self.sync_blocks()
        assert txid not in n0.getrawmempool(), "aggregated send did not confirm"
        self.wait_until(
            lambda: Decimal(str(w1.getbalances()["mine"]["trusted"])) >= recv_before + Decimal("1.0") - Decimal("0.1"),
            timeout=120)
        self.log.info("default-aggregated plain send confirmed")

        # --- The producer's wallet must not report its cover half as a send. ---
        # w1's coin was spent and returned in full as change while the
        # initiator (w0) funded the aggregate's whole fee, so the tx's net
        # effect on w1 is the genuine 1.0 payment it received -- nothing else.
        # A regression here surfaces served candidates as spontaneous
        # "send -fee / fee" entries in the producer's transaction list.
        entries = [e for e in w1.listtransactions("*", 1000) if e["txid"] == txid]
        assert entries, "producer wallet does not know the aggregate tx"
        categories = [e["category"] for e in entries]
        assert "send" not in categories, \
            "cover half surfaced as a send in the producer's wallet: %r" % entries
        received = [e for e in entries if e["category"] == "receive"]
        assert_equal(len(received), 1)
        assert_equal(Decimal(str(received[0]["amount"])), Decimal("1.0"))
        self.log.info("producer wallet reports only the received payment")

        # --- Node1 opted out (-aggregatesends=0): its pooled candidates stay. ---
        self.serve_candidate(n1, n0, w0)
        before = n1.getaggregationhint()["available"]
        assert before >= 1
        w1.sendtoblsctaddress(w0.getnewaddress(label="", address_type="blsct"), 1.0)
        self.wait_until(lambda: len(n1.getrawmempool()) >= 1, timeout=60)
        assert_equal(n1.getaggregationhint()["available"], before)
        self.generatetoblsctaddress(n1, 1, miner1)
        self.sync_blocks()
        self.log.info("opt-out plain send left the pool untouched")

        # --- consolidate merges pooled cover candidates by default, too. ---
        # A consolidation is the most linkable tx a wallet broadcasts (every
        # input and the single output are its own), so it takes the same
        # aggregation path as a plain send.
        cand_inputs = self.serve_candidate(n0, n1, w1)
        unspent_before = {u["outid"]: Decimal(str(u["amount"])) for u in w0.listblsctunspent()}
        txids = w0.consolidate(1)
        assert_equal(len(txids), 1)
        self.wait_until(lambda: txids[0] in n0.getrawmempool(), timeout=60)
        tx = n0.getrawtransaction(txids[0], True)
        broadcast_prevouts = {vin["outid"] for vin in tx["vin"] if "outid" in vin}
        assert cand_inputs, "replycandidate returned no inputs; the outpoint assertion below would be vacuous"
        for outpoint in cand_inputs:
            assert outpoint in broadcast_prevouts, (
                "candidate input %s missing from consolidation tx inputs %r" % (outpoint, sorted(broadcast_prevouts)))
        # Merging the candidate means the returned txid is the COMBINED tx's
        # id (own inputs + cover input, own output + cover output), and the
        # candidate was evicted from the pool.
        assert len(tx["vin"]) >= 3, "consolidation did not merge >=2 own inputs + the cover input: %r" % tx["vin"]
        assert len(tx["vout"]) >= 2, "combined tx lost the cover candidate's output: %r" % len(tx["vout"])
        assert_equal(n0.getaggregationhint()["available"], 0)
        # Confirm; the merged small outputs must be spendable as one afterwards.
        self.generatetoblsctaddress(n0, 1, miner0)
        self.sync_blocks()
        assert txids[0] not in n0.getrawmempool(), "aggregated consolidation did not confirm"
        own_inputs = broadcast_prevouts - set(cand_inputs)
        assert own_inputs <= unspent_before.keys(), "consolidation spent a coin w0 did not list as unspent"
        fee = sum(Decimal(str(out["value"])) for out in tx["vout"])
        merged = Decimal(sum(unspent_before[outid] for outid in own_inputs)) - fee
        unspent_after = {u["outid"]: u for u in w0.listblsctunspent()}
        own_outputs = [unspent_after[out["hash"]] for out in tx["vout"] if out["hash"] in unspent_after]
        assert_equal(len(own_outputs), 1)
        assert own_outputs[0]["spendable"], "consolidated output is not spendable: %r" % own_outputs[0]
        assert_equal(Decimal(str(own_outputs[0]["amount"])), merged)
        self.log.info("default-aggregated consolidation confirmed")

        # --- consolidate N>1: each consolidation spends coins of its own. ---
        # consolidate holds the wallet lock throughout, so the mempool sync
        # callback cannot tell the wallet of the aggregated first transaction
        # until the call returns. The second iteration must still not reselect
        # the first one's coins: it would build a conflicting double-spend.
        #
        # consolidate(1) merged every coin w0 had, and the coinbases maturing
        # now are w1's, so give w0 four small coins to merge in pairs. Node1
        # runs -aggregatesends=0, so these sends leave node0's pool alone.
        for _ in range(4):
            w1.sendtoblsctaddress(w0.getnewaddress(label="", address_type="blsct"), 1.0)
        self.wait_until(lambda: len(n1.getrawmempool()) == 4, timeout=60)
        self.generatetoblsctaddress(n1, 1, miner1)
        self.sync_blocks()
        cand_inputs = self.serve_candidate(n0, n1, w1)
        txids = w0.consolidate(2, 2)
        assert_equal(len(txids), 2)
        self.wait_until(lambda: set(txids) <= set(n0.getrawmempool()), timeout=60)
        prevouts = [{vin["outid"] for vin in n0.getrawtransaction(txid, True)["vin"]} for txid in txids]
        assert not prevouts[0] & prevouts[1], "consolidations share inputs: %r" % sorted(prevouts[0] & prevouts[1])
        # The first merged the only pooled cover; the second found the pool
        # empty and went out plain.
        assert set(cand_inputs) <= prevouts[0], "first consolidation did not merge the cover"
        assert_equal(len(prevouts[0]), 2 + len(cand_inputs))
        assert_equal(len(prevouts[1]), 2)
        self.generatetoblsctaddress(n0, 1, miner0)
        self.sync_blocks()
        assert not set(txids) & set(n0.getrawmempool()), "a consolidation did not confirm"
        self.log.info("consolidate 2 broadcast two non-conflicting consolidations")

        # --- Input-derived cover sizing: a small send leaves covers pooled. ---
        # The cover cap is one candidate per COVER_INPUT_RATIO own inputs, so a
        # send with at most that many inputs takes one cover even though the
        # pool holds two. The arithmetic alone is pinned by
        # target_cover_count_ceil_and_clamp; this checks the send path uses it.
        COVER_INPUT_RATIO = 4
        self.serve_candidate(n0, n1, w1)
        self.serve_candidate(n0, n1, w1)
        pooled = n0.getaggregationhint()["available"]
        assert_equal(pooled, 2)
        trusted_before = Decimal(str(w0.getbalances()["mine"]["trusted"]))
        res = w0.aggregatesend(w1.getnewaddress(label="", address_type="blsct"), 1.0, 16)
        tx = n0.getrawtransaction(res["txid"], True)
        own_inputs = len(tx["vin"]) - res["candidates_merged"]
        expected = -(-own_inputs // COVER_INPUT_RATIO)
        assert expected < pooled, "own half has %d inputs; the cap would not bind" % own_inputs
        assert_equal(res["candidates_merged"], expected)
        assert_equal(n0.getaggregationhint()["available"], pooled - expected)
        # aggregatesend records the aggregate as the wallet's own send, so
        # the change of its own half is trusted at once. When only the sync
        # callback adds it, the cover input leaves it untrusted until it
        # confirms.
        n0.syncwithvalidationinterfacequeue()
        assert_equal(w0.getbalances()["mine"]["untrusted_pending"], 0)
        # w0 paid the 1.0 and the whole fee; the cover half is fee-0.
        trusted = trusted_before - Decimal("1.0") - self.tx_fee(tx)
        assert_equal(Decimal(str(w0.getbalances()["mine"]["trusted"])), trusted)
        # A chained send of the whole trusted balance needs the aggregate's
        # change: the other coins alone fall short of it.
        aggregate_outputs = {out["hash"] for out in tx["vout"]}
        other_coins = sum(Decimal(str(u["amount"])) for u in w0.listblsctunspent(0) if u["outid"] not in aggregate_outputs)
        assert other_coins < trusted, "w0 can fund the chained send without the aggregate's change"
        w0.sendtoblsctaddress(w0.getnewaddress(label="", address_type="blsct"), trusted, "", False, True)
        self.generatetoblsctaddress(n0, 1, miner0)
        self.sync_blocks()
        assert res["txid"] not in n0.getrawmempool(), "cover-sized aggregatesend did not confirm"
        assert_equal(n0.getrawmempool(), [])
        self.log.info("small aggregatesend merged %d of %d pooled covers" % (expected, pooled))

        fee_aggregated, fee_plain = self.test_back_to_back_consolidations()
        self.test_consolidate_opt_out()
        self.test_consolidate_evicts_on_failed_broadcast(fee_aggregated, fee_plain)

    @staticmethod
    def tx_fee(tx):
        # The fee output is the only one carrying a plain value.
        return sum(Decimal(str(out["value"])) for out in tx["vout"])

    def test_back_to_back_consolidations(self):
        """Two consolidate calls in a row: the wallet records the first call's
        aggregate as its own when broadcast, rather than waiting for the
        mempool sync callback, so the second call cannot reselect its coins
        and the merged output is trusted at once."""
        n0, n1 = self.nodes
        w0 = n0.get_wallet_rpc("w0")
        w1 = n1.get_wallet_rpc("w1")
        miner0 = w0.getnewaddress(label="", address_type="blsct")

        # Give w0 four coins smaller than any it holds, so each consolidate(1, 2)
        # merges two of them. Self-sends, because w0's default aggregation
        # drains the pool cover the previous section left, which may otherwise
        # have gone stale by the time the consolidation below picks it.
        for _ in range(4):
            w0.sendtoblsctaddress(w0.getnewaddress(label="", address_type="blsct"), 0.5)
        self.generatetoblsctaddress(n0, 1, miner0)
        self.sync_blocks()
        assert_equal(n0.getaggregationhint()["available"], 0)
        cand_inputs = self.serve_candidate(n0, n1, w1)

        # No wait between the calls. Without the record, the second call races
        # the mempool sync callback for the first one's spend; the callback
        # usually wins, so the disjoint-inputs check below only catches that
        # sometimes. The trust check after it does not depend on the race.
        first = w0.consolidate(1, 2)
        second = w0.consolidate(1, 2)
        assert_equal(len(first), 1)
        assert_equal(len(second), 1)

        mempool = n0.getrawmempool()
        assert first[0] in mempool and second[0] in mempool, "a consolidation is missing from the mempool"
        txs = [n0.getrawtransaction(txid, True) for txid in (first[0], second[0])]
        prevouts = [{vin["outid"] for vin in tx["vin"]} for tx in txs]
        assert not prevouts[0] & prevouts[1], "consolidations share inputs: %r" % sorted(prevouts[0] & prevouts[1])
        assert set(cand_inputs) <= prevouts[0], "first consolidation did not merge the cover"
        assert_equal(len(prevouts[0]), 2 + len(cand_inputs))
        assert_equal(len(prevouts[1]), 2)

        # The aggregate's merged output belongs to the wallet's own half, so
        # it is trusted. When only the sync callback adds the aggregate, the
        # cover input makes the whole tx untrusted until it confirms.
        n0.syncwithvalidationinterfacequeue()
        assert_equal(w0.getbalances()["mine"]["untrusted_pending"], 0)

        self.generatetoblsctaddress(n0, 1, miner0)
        self.sync_blocks()
        assert not {first[0], second[0]} & set(n0.getrawmempool()), "a consolidation did not confirm"
        self.log.info("back-to-back consolidations recorded and spent disjoint coins")
        return self.tx_fee(txs[0]), self.tx_fee(txs[1])

    def test_consolidate_opt_out(self):
        """consolidate on the -aggregatesends=0 node leaves its pool alone."""
        n0, n1 = self.nodes
        w0 = n0.get_wallet_rpc("w0")
        w1 = n1.get_wallet_rpc("w1")
        miner1 = w1.getnewaddress(label="", address_type="blsct")

        cand_inputs = self.serve_candidate(n1, n0, w0)
        before = n1.getaggregationhint()["available"]
        txids = w1.consolidate(1, 2)
        assert_equal(len(txids), 1)
        tx = n1.getrawtransaction(txids[0], True)
        prevouts = {vin["outid"] for vin in tx["vin"]}
        assert_equal(len(prevouts), 2)
        assert not set(cand_inputs) & prevouts, "opt-out consolidation merged a pooled candidate"
        assert_equal(n1.getaggregationhint()["available"], before)
        self.generatetoblsctaddress(n1, 1, miner1)
        self.sync_blocks()
        self.log.info("opt-out consolidation left the pool untouched")

    def test_consolidate_evicts_on_failed_broadcast(self, fee_aggregated, fee_plain):
        """A -maxtxfee between the plain and the aggregated consolidation fee
        makes the aggregate's broadcast fail (max fee exceeded) while the plain
        fallback goes out. The cover candidate picked for the failed aggregate
        is evicted, so it cannot poison the next consolidation."""
        n0, n1 = self.nodes
        assert fee_plain < fee_aggregated, "cover did not raise the fee: %s vs %s" % (fee_plain, fee_aggregated)
        max_fee = ((fee_plain + fee_aggregated) / 2).quantize(Decimal("0.00000001"))
        self.restart_node(0, extra_args=PULL_ARGS + ["-maxtxfee=%s" % max_fee])
        if "w0" not in n0.listwallets():
            n0.loadwallet("w0")
        self.connect_nodes(0, 1)
        w0 = n0.get_wallet_rpc("w0")
        w1 = n1.get_wallet_rpc("w1")
        # Node1 still queues pull requests from before the restart, whose reply
        # keys node0 no longer holds: a candidate served to one is never pooled.
        n1.listpendingcandidaterequests(1000)

        cand_inputs = self.serve_candidate(n0, n1, w1)
        assert_equal(n0.getaggregationhint()["available"], 1)
        txids = w0.consolidate(1, 2)
        assert_equal(len(txids), 1)
        tx = n0.getrawtransaction(txids[0], True)
        prevouts = {vin["outid"] for vin in tx["vin"]}
        assert_equal(len(prevouts), 2)
        assert not set(cand_inputs) & prevouts, "consolidation over -maxtxfee still merged the candidate"
        assert self.tx_fee(tx) <= max_fee
        assert_equal(n0.getaggregationhint()["available"], 0)
        self.log.info("candidate evicted after the aggregate exceeded -maxtxfee")


if __name__ == "__main__":
    P2PMsgDefaultAggregateTest(__file__).main()
