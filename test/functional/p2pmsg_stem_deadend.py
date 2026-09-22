#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Encrypted p2p messaging: a Dandelion++ stem must not dead-end.

A stem hop is a single unicast. If it lands on a node whose only relaying
p2pmsg peer is the node it came from, that node cannot fluff onward -- the
flood excludes the origin -- and the message silently disappears. Leaves do
not rescue it either: a leaf forwards nothing, so fluffing to one is not the
flood escaping the node. The same holds when the receiving node rolls the
stem packet over into fluff, which it does with some probability.

The node must instead hand the envelope back to the origin as a FLUFF copy.
The origin has so far only stem-relayed it, so its duplicate-rescue path
floods it onward and the message survives.

Topology: two nodes, B (originator) and A (the stem successor and dead end),
with a receive-only leaf watching each. A's only relay peer is B.

    leaf_a -- A === B -- leaf_b

PoW difficulty is 1 bit so the test does not burn CPU.
"""

from test_framework.messages import NODE_P2PMSG_LEAF
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PMsgStemDeadEndTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-p2pmsg=1", "-p2pmsgpowbits=1"]] * 2

    def run_test(self):
        # The framework has already connected node 0 to node 1; that single
        # link is what makes A a dead end.
        node_b, node_a = self.nodes[0], self.nodes[1]

        # Leaves only: they receive fluff and are never stem successors, so B's
        # single stem-eligible peer is A and the stem hop is deterministic.
        self.log.info("Attach a receive-only leaf to each node")
        leaf_b = node_b.add_p2p_connection(P2PInterface(), services=NODE_P2PMSG_LEAF)
        leaf_a = node_a.add_p2p_connection(P2PInterface(), services=NODE_P2PMSG_LEAF)
        leaf_b.sync_with_ping()
        leaf_a.sync_with_ping()

        info_b = node_b.getp2pmsginfo()
        assert_equal(info_b["relay_capable_peers"], 1)  # A, and only A
        assert_equal(info_b["leaf_peers"], 1)
        assert_equal(node_a.getp2pmsginfo()["relay_capable_peers"], 1)

        # Originate a stem message at B. B unicasts it to A; A has no relaying
        # peer but B, so without the hand-back the message ends there and
        # neither leaf ever sees it.
        self.log.info("Stem send from B: A dead-ends it and must hand it back")
        assert_equal(node_b.sendp2pping(node_a.getp2pmsginfo()["inbox_pubkey"], True), True)

        # A fluffs to its own leaf on arrival...
        leaf_a.wait_until(lambda: leaf_a.message_count["p2pmsg"] >= 1, timeout=30)
        # ...and hands the envelope back to B, whose duplicate-rescue floods it
        # to everyone except A. That copy reaching leaf_b is the whole point:
        # before the hand-back it never arrived.
        leaf_b.wait_until(lambda: leaf_b.message_count["p2pmsg"] >= 1, timeout=30)

        # A stem hop is a unicast between nodes; neither leaf is ever a stem
        # successor, so neither may see a dp2pmsg.
        assert_equal(leaf_a.message_count["dp2pmsg"], 0)
        assert_equal(leaf_b.message_count["dp2pmsg"], 0)

        # The hand-back must terminate. Each node relays a given envelope at
        # most twice (once on arrival, once as a duplicate rescue), so the
        # exchange between two dead ends settles after a bounded number of
        # copies instead of ping-ponging forever. A leaf may legitimately see
        # the envelope twice; what matters is that it stops.
        self.log.info("The rescue terminates")
        leaf_a.sync_with_ping()
        leaf_b.sync_with_ping()
        settled = (leaf_a.message_count["p2pmsg"], leaf_b.message_count["p2pmsg"])
        assert settled[0] <= 2, settled
        assert settled[1] <= 2, settled
        leaf_a.sync_with_ping()
        leaf_b.sync_with_ping()
        assert_equal((leaf_a.message_count["p2pmsg"], leaf_b.message_count["p2pmsg"]), settled)

        self.log.info("p2pmsg stem dead-end OK")


if __name__ == "__main__":
    P2PMsgStemDeadEndTest(__file__).main()
