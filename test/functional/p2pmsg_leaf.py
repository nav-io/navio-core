#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Encrypted p2p messaging: NODE_P2PMSG_LEAF receive-only peers.

A leaf (NODE_P2PMSG_LEAF, no NODE_P2PMSG) is a bus client that wants fluff
traffic delivered but never relays. The node must:

  * fluff P2PMSG to it like any relay-capable peer;
  * never pick it as the Dandelion++ stem successor (it would black-hole the
    stem), so with only a leaf connected a stem send falls back to fluff and
    the leaf sees `p2pmsg`, not `dp2pmsg`;
  * once a NODE_P2PMSG relay is also connected, route stem sends to the relay
    (`dp2pmsg`) while the leaf still only ever sees `p2pmsg`;
  * count it in getp2pmsginfo()['leaf_peers'] and not in relay_capable_peers.

PoW difficulty is set to 1 bit so the test does not burn CPU.
"""

from test_framework.messages import NODE_P2PMSG, NODE_P2PMSG_LEAF
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PMsgLeafTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-p2pmsg=1", "-p2pmsgpowbits=1"]]

    def run_test(self):
        node = self.nodes[0]
        info = node.getp2pmsginfo()
        assert_equal(info["enabled"], True)
        inbox = info["inbox_pubkey"]
        assert_equal(info["relay_capable_peers"], 0)
        assert_equal(info["leaf_peers"], 0)

        # A leaf advertises only NODE_P2PMSG_LEAF: it is not a full node and it
        # does not relay the overlay.
        self.log.info("Connect a leaf peer (NODE_P2PMSG_LEAF only)")
        leaf = node.add_p2p_connection(P2PInterface(), services=NODE_P2PMSG_LEAF)
        # Make sure the node has processed our verack (so ForEachNode sees the
        # peer as fully connected) before it originates anything.
        leaf.sync_with_ping()
        info = node.getp2pmsginfo()
        assert_equal(info["relay_capable_peers"], 0)
        assert_equal(info["leaf_peers"], 1)

        # Stem send with only a leaf connected: there is no stem-eligible
        # successor, so the node must fluff. The leaf gets a plain `p2pmsg`
        # and never a `dp2pmsg`.
        self.log.info("Stem send with only a leaf: node fluffs to the leaf")
        assert_equal(node.sendp2pping(inbox, True), True)
        leaf.wait_until(lambda: leaf.message_count["p2pmsg"] >= 1, timeout=20)
        assert_equal(leaf.message_count["dp2pmsg"], 0)

        # An explicit fluff send also lands on the leaf.
        self.log.info("Fluff send: leaf receives it")
        assert_equal(node.sendp2pping(inbox, False), True)
        leaf.wait_until(lambda: leaf.message_count["p2pmsg"] >= 2, timeout=20)
        assert_equal(leaf.message_count["dp2pmsg"], 0)

        # Now add a relay-capable peer. It becomes the only stem-eligible
        # successor, so a stem send goes to it as `dp2pmsg` and the leaf sees
        # nothing new (a stem hop is a single unicast).
        self.log.info("Connect a relay peer (NODE_P2PMSG); stem goes to it, not the leaf")
        relay = node.add_p2p_connection(P2PInterface(), services=NODE_P2PMSG)
        relay.sync_with_ping()
        info = node.getp2pmsginfo()
        assert_equal(info["relay_capable_peers"], 1)
        assert_equal(info["leaf_peers"], 1)

        leaf_fluffs = leaf.message_count["p2pmsg"]
        assert_equal(node.sendp2pping(inbox, True), True)
        relay.wait_until(lambda: relay.message_count["dp2pmsg"] >= 1, timeout=20)
        # Fence: a fluff send reaches both peers; once the leaf has it, any
        # earlier (mis)delivery of the stem message would already be visible.
        assert_equal(node.sendp2pping(inbox, False), True)
        leaf.wait_until(lambda: leaf.message_count["p2pmsg"] >= leaf_fluffs + 1, timeout=20)
        relay.wait_until(lambda: relay.message_count["p2pmsg"] >= 1, timeout=20)
        assert_equal(leaf.message_count["dp2pmsg"], 0)
        assert_equal(leaf.message_count["p2pmsg"], leaf_fluffs + 1)
        assert_equal(relay.message_count["dp2pmsg"], 1)

        # Dropping the leaf leaves only the relay counted.
        self.log.info("Disconnect the leaf: leaf_peers drops to 0")
        leaf.peer_disconnect()
        leaf.wait_for_disconnect()
        self.wait_until(lambda: node.getp2pmsginfo()["leaf_peers"] == 0, timeout=20)
        assert_equal(node.getp2pmsginfo()["relay_capable_peers"], 1)

        self.log.info("p2pmsg leaf OK")


if __name__ == "__main__":
    P2PMsgLeafTest(__file__).main()
