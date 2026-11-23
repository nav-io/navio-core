#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""The per-coin privacy score (privacy_bits) of BLSCT wallets.

    privacy_bits(coin) = log2(foreign inputs + 1) + min(privacy_bits(own inputs))

A producer wallet on node1 serves its coin to node0 as a cover candidate.
Checked, for an output-storage producer and a full-transaction one:

- a plain receive scores 0, in listblsctunspent and listunspent;
- node0's aggregate spends two coins of node0's and pays the producer. The
  served coin coming back and the payment to the producer both score
  log2(N + 1), N being the aggregate's inputs that are not the producer's:
  every coin of ours in a tx spending one of our coins scores alike, a
  payment received inside it included. node0's change scores log2(M + 1),
  M being the inputs that are not node0's;
- an own send's change takes the lowest score of the coins it spends: the
  mixed coin alone keeps its score, together with a fresh receive it drops
  to 0;
- the scores survive a restart and rescanblockchain rebuilds the same ones.
"""

import math
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PULL_ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1", "-candidatepullinterval=2", "-servecandidates=0"]


def expected_bits(foreign, prev=Decimal(0)):
    """floor(1000 * log2(foreign + 1)) / 1000 + prev, as the wallet computes it."""
    n = foreign + 1
    milli = 1000 * (n.bit_length() - 1) if n & (n - 1) == 0 else math.floor(1000 * math.log2(n))
    return Decimal(milli) / 1000 + prev


class BLSCTPrivacyScoreTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        # Node1 sends plain transfers, so its sends merge no covers.
        self.extra_args = [PULL_ARGS, PULL_ARGS + ["-aggregatesends=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def mine(self, node, num_blocks, batch_size=4):
        remaining = num_blocks
        while remaining > 0:
            to = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to, self.funder_addr)
            remaining -= to
        self.sync_blocks()

    def addr(self, wallet, label=""):
        return wallet.getnewaddress(label=label, address_type="blsct")

    def scores(self, wallet):
        """privacy_bits of every coin, by outid, checking both listings agree."""
        blsct = {u["outid"]: u["privacy_bits"] for u in wallet.listblsctunspent()}
        listed = {u["outid"]: u["privacy_bits"] for u in wallet.listunspent() if "privacy_bits" in u}
        assert_equal(blsct, listed)
        return blsct

    def wait_new_coins(self, wallet, before):
        """Wait until the wallet's coins differ from `before` (a set of outids)."""
        self.wait_until(lambda: set(self.scores(wallet)) != before, timeout=60)

    def wait_mempool(self, node, count):
        self.wait_until(lambda: len(node.getrawmempool()) == count, timeout=60)

    def run_test(self):
        n1 = self.nodes[1]
        n1.createwallet(wallet_name="funder", blsct=True, storage_output=True)
        self.funder = n1.get_wallet_rpc("funder")
        self.funder_addr = self.addr(self.funder)
        self.mine(n1, 110)
        for storage in (True, False):
            self.check_producer(storage)

    def check_producer(self, storage):
        n0, n1 = self.nodes
        suffix = "storage" if storage else "full"
        self.log.info(f"Producer wallet with storage_output={storage}")
        n0.createwallet(wallet_name=f"sender_{suffix}", blsct=True, storage_output=True)
        n1.createwallet(wallet_name=f"producer_{suffix}", blsct=True, storage_output=storage)
        sender = n0.get_wallet_rpc(f"sender_{suffix}")
        producer = n1.get_wallet_rpc(f"producer_{suffix}")

        self.log.info("A plain receive scores 0")
        self.funder.sendtoblsctaddress(self.addr(producer), 10)
        # Two coins for the sender, which its send spends both of, so the
        # producer's coin is mixed with two foreign inputs.
        self.funder.sendtoblsctaddress(self.addr(sender), 10)
        self.funder.sendtoblsctaddress(self.addr(sender), 10)
        self.wait_mempool(n1, 3)
        # Two blocks: a served candidate must spend a coin with two
        # confirmations.
        self.mine(n1, 2)
        self.wait_until(lambda: len(sender.listblsctunspent()) == 2, timeout=60)
        [(cover_coin, score)] = self.scores(producer).items()
        assert_equal(score, Decimal(0))
        assert_equal(list(self.scores(sender).values()), [Decimal(0)] * 2)

        self.log.info("Serve the producer's coin to node0 as a cover candidate")
        keys = []

        def got_one():
            keys[:] = n1.listpendingcandidaterequests()
            return len(keys) > 0

        self.wait_until(got_one, timeout=120)
        reply = producer.replycandidate(keys[0])
        assert_equal(reply["inputs"], [cover_coin])
        self.wait_until(lambda: n0.getaggregationhint()["available"] == 1, timeout=120)

        self.log.info("node0's send merges the cover, pays the producer, and is mined")
        sender.sendtoblsctaddress(self.addr(producer), 15)
        self.wait_mempool(n0, 1)
        self.mine(n0, 1)
        assert_equal(n0.getrawmempool(), [])
        # Score from the transaction actually mined, the one spending the cover.
        block = n0.getblock(n0.getbestblockhash(), 2)
        [mined] = [tx for tx in block["tx"] if cover_coin in {vin.get("outid") for vin in tx["vin"]}]
        inputs = len(mined["vin"])
        assert inputs >= 3, mined
        self.log.info(f"The aggregate has {inputs} inputs")

        self.log.info("The served coin and the payment both score log2(N + 1), N the other inputs")
        self.wait_until(lambda: len(self.scores(producer)) == 2 and cover_coin not in self.scores(producer), timeout=60)
        mixed_score = expected_bits(inputs - 1)
        assert_equal(list(self.scores(producer).values()), [mixed_score] * 2)
        self.log.info("node0's change scores log2(M + 1), M the inputs not node0's")
        self.wait_until(lambda: len(self.scores(sender)) == 1, timeout=60)
        [sender_score] = self.scores(sender).values()
        # The sender's own inputs are its two coins; every other input is foreign.
        assert_equal(sender_score, expected_bits(inputs - 2))
        assert sender_score < mixed_score

        self.log.info("An own send spending mixed coins only keeps their score")
        self.funder_receive = self.addr(self.funder)
        before = set(self.scores(producer))
        producer.sendtoblsctaddress(self.funder_receive, 2)
        self.wait_mempool(n1, 1)
        self.mine(n1, 1)
        self.wait_new_coins(producer, before)
        assert_equal(list(self.scores(producer).values()), [mixed_score] * 2)

        self.log.info("Spent together with a fresh receive, the change drops to the lower score, 0")
        self.funder.sendtoblsctaddress(self.addr(producer), 10)
        self.wait_mempool(n1, 1)
        self.mine(n1, 1)
        self.wait_until(lambda: sorted(self.scores(producer).values()) == [Decimal(0), mixed_score, mixed_score], timeout=60)
        # The producer holds 10 (fresh), 10 and about 13 (mixed): 25 spends all.
        producer.sendtoblsctaddress(self.funder_receive, 25)
        self.wait_mempool(n1, 1)
        self.mine(n1, 1)
        self.wait_until(lambda: len(self.scores(producer)) == 1, timeout=60)
        assert_equal(list(self.scores(producer).values()), [Decimal(0)])

        self.log.info("Scores survive a restart; rescanblockchain rebuilds the same ones")
        before = self.scores(sender)
        n0.unloadwallet(f"sender_{suffix}")
        n0.loadwallet(f"sender_{suffix}")
        assert_equal(self.scores(sender), before)
        sender.rescanblockchain()
        assert_equal(self.scores(sender), before)
        before = self.scores(producer)
        producer.rescanblockchain()
        assert_equal(self.scores(producer), before)


if __name__ == "__main__":
    BLSCTPrivacyScoreTest(__file__).main()
