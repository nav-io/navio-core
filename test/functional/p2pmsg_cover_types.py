#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Type-aware cover selection on the default send path.

Whether a prev-out was a block reward is public, so cover candidates only
blend when their input type mirrors the initiator's own inputs. Node1 serves
node0 two candidates spending block rewards (from a wallet that only ever
mined) and two spending transfers (from a wallet only ever paid). A plain send
on node0 from a wallet holding only reward outputs must then merge a
reward-backed cover, and one from a wallet holding only transfer outputs must
merge a transfer-backed cover.

This exercises the pool admission classification (MarkRewardInput),
CountRewardInputs and RefineCoverSelection end to end.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PULL_ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1", "-candidatepullinterval=2", "-servecandidates=0", "-debug=net"]


class P2PMsgCoverTypesTest(BitcoinTestFramework):
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

    def mine(self, node, address, num_blocks, batch_size=4):
        remaining = num_blocks
        while remaining > 0:
            to = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to, address)
            remaining -= to
        self.sync_blocks()

    def serve_candidate(self, producer_wallet):
        """Claim one of node0's pull requests on node1, answer it from
        `producer_wallet`, and wait for node0 to pool the candidate."""
        n0, n1 = self.nodes
        keys = []

        def got_one():
            keys.extend(n1.listpendingcandidaterequests())
            return len(keys) > 0

        self.wait_until(got_one, timeout=120)
        before = n0.getaggregationhint()["available"]
        reply = producer_wallet.replycandidate(keys[0])
        self.wait_until(lambda: n0.getaggregationhint()["available"] > before, timeout=120)
        assert reply["inputs"], "replycandidate returned no inputs; the type assertions would be vacuous"
        return set(reply["inputs"])

    def send_and_get_prevouts(self, node, wallet, dest, known_txids):
        wallet.sendtoblsctaddress(dest, 1.0)
        self.wait_until(lambda: len(set(node.getrawmempool()) - known_txids) == 1, timeout=60)
        txid = (set(node.getrawmempool()) - known_txids).pop()
        tx = node.getrawtransaction(txid, True)
        return txid, {vin["outid"] for vin in tx["vin"] if "outid" in vin}

    def run_test(self):
        n0, n1 = self.nodes
        for node, name in ((n0, "reward_sender"), (n0, "transfer_sender"),
                           (n1, "reward_producer"), (n1, "transfer_producer"), (n1, "funder")):
            node.createwallet(wallet_name=name, blsct=True, storage_output=True)
        reward_sender = n0.get_wallet_rpc("reward_sender")
        transfer_sender = n0.get_wallet_rpc("transfer_sender")
        reward_producer = n1.get_wallet_rpc("reward_producer")
        transfer_producer = n1.get_wallet_rpc("transfer_producer")
        funder = n1.get_wallet_rpc("funder")

        def addr(wallet):
            return wallet.getnewaddress(label="", address_type="blsct")

        self.log.info("Fund reward-only wallets by mining and transfer-only wallets by payment")
        self.mine(n1, addr(reward_producer), 10)
        self.mine(n0, addr(reward_sender), 10)
        self.mine(n1, addr(funder), 110)
        # Two transfer outputs for two candidates, one for the transfer sender.
        # Node1 runs -aggregatesends=0, so these are plain transfers.
        for wallet in (transfer_producer, transfer_producer, transfer_sender):
            funder.sendtoblsctaddress(addr(wallet), 10)
        self.wait_until(lambda: len(n1.getrawmempool()) == 3, timeout=60)
        self.mine(n1, addr(funder), 1)
        self.wait_until(lambda: len(transfer_sender.listblsctunspent()) == 1, timeout=60)

        self.log.info("Pool two reward-backed and two transfer-backed candidates on node0")
        reward_inputs = self.serve_candidate(reward_producer) | self.serve_candidate(reward_producer)
        transfer_inputs = self.serve_candidate(transfer_producer) | self.serve_candidate(transfer_producer)
        assert_equal(len(reward_inputs), 2)
        assert_equal(len(transfer_inputs), 2)
        assert_equal(n0.getaggregationhint()["available"], 4)

        dest = addr(funder)
        with n0.assert_debug_log(expected_msgs=[], unexpected_msgs=["cover refinement skipped"]):
            self.log.info("A send spending block rewards merges a reward-backed cover")
            txid, prevouts = self.send_and_get_prevouts(n0, reward_sender, dest, set())
            assert prevouts & reward_inputs, "no reward-backed cover in %r" % sorted(prevouts)
            assert not prevouts & transfer_inputs, "transfer-backed cover merged: %r" % sorted(prevouts & transfer_inputs)
            assert_equal(n0.getaggregationhint()["available"], 3)

            self.log.info("A send spending transfers merges a transfer-backed cover")
            _, prevouts = self.send_and_get_prevouts(n0, transfer_sender, dest, {txid})
            assert prevouts & transfer_inputs, "no transfer-backed cover in %r" % sorted(prevouts)
            assert not prevouts & reward_inputs, "reward-backed cover merged: %r" % sorted(prevouts & reward_inputs)
            assert_equal(n0.getaggregationhint()["available"], 2)

        self.mine(n0, addr(funder), 1)
        assert_equal(n0.getrawmempool(), [])


if __name__ == "__main__":
    P2PMsgCoverTypesTest(__file__).main()
