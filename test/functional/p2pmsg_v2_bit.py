#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Encrypted p2p messaging: envelope v2 has a service bit of its own.

A node that speaks envelope v1 cannot parse a v2 envelope. It does not shrug:
OnWire() returns RejectInvalid and the caller charges 10 discouragement points,
so ten envelopes disconnect the sender and a reconnecting peer starts again.
Routing blind between the formats is therefore hostile in both directions --
an upgraded node flooding the overlay would be discouraged right across the
un-upgraded network.

NODE_P2PMSG_V2 keeps them apart. This test pins the routing half of that:

  * the node advertises NODE_P2PMSG_V2 and NOT NODE_P2PMSG, so a v1 peer never
    sends it v1 traffic and never expects to receive any;
  * a peer advertising only NODE_P2PMSG gets no p2pmsg at all, in either
    phase -- it is not fluff-eligible and not a stem candidate;
  * nor does a LEAF that names no format: the leaf bit says "do not stem to
    me", not which envelopes to send;
  * a peer advertising NODE_P2PMSG_V2 gets both;
  * getp2pmsginfo counts the v2 bit, not the v1 one.

PoW difficulty is 1 bit so the test does not burn CPU.
"""

from test_framework.messages import NODE_P2PMSG, NODE_P2PMSG_LEAF, NODE_P2PMSG_V2
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PMsgV2BitTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-p2pmsg=1", "-p2pmsgpowbits=1"]]

    def run_test(self):
        node = self.nodes[0]

        # What we advertise is what peers route on. v1 must not be claimed: this
        # build rejects a v1 header, so claiming it invites traffic we answer
        # with discouragement points.
        self.log.info("The node advertises the v2 bit and not the v1 bit")
        services = int(node.getnetworkinfo()["localservices"], 16)
        assert services & NODE_P2PMSG_V2, "NODE_P2PMSG_V2 not advertised"
        assert not (services & NODE_P2PMSG), "NODE_P2PMSG (v1) must not be advertised"

        inbox = node.getp2pmsginfo()["inbox_pubkey"]

        # A v1-only peer. It would be charged 10 points per envelope it could
        # not parse, so it must be sent none.
        self.log.info("A v1-only peer is sent nothing, in either phase")
        old = node.add_p2p_connection(P2PInterface(), services=NODE_P2PMSG)
        old.sync_with_ping()
        info = node.getp2pmsginfo()
        assert_equal(info["relay_capable_peers"], 0)  # v1 does not count
        assert_equal(info["leaf_peers"], 0)

        # With no v2 peer at all, a stem send has no successor and falls back to
        # fluff -- and the fluff must not reach the v1 peer either.
        assert_equal(node.sendp2pping(inbox, True), True)
        assert_equal(node.sendp2pping(inbox, False), True)
        old.sync_with_ping()
        assert_equal(old.message_count.get("p2pmsg", 0), 0)
        assert_equal(old.message_count.get("dp2pmsg", 0), 0)

        # A v2 relay is eligible for both phases.
        self.log.info("A v2 peer is sent both fluff and stem")
        new = node.add_p2p_connection(P2PInterface(), services=NODE_P2PMSG_V2)
        new.sync_with_ping()
        assert_equal(node.getp2pmsginfo()["relay_capable_peers"], 1)

        assert_equal(node.sendp2pping(inbox, False), True)
        new.wait_until(lambda: new.message_count.get("p2pmsg", 0) >= 1, timeout=30)
        assert_equal(node.sendp2pping(inbox, True), True)
        new.wait_until(lambda: new.message_count.get("dp2pmsg", 0) >= 1, timeout=30)

        # The v1 peer has still had nothing, through all of it.
        old.sync_with_ping()
        assert_equal(old.message_count.get("p2pmsg", 0), 0)
        assert_equal(old.message_count.get("dp2pmsg", 0), 0)

        # A leaf that names no format is in the same position as the v1 peer:
        # the leaf bit says "do not stem to me", not which envelopes to send.
        self.log.info("A leaf that names no format is sent nothing either")
        bare = node.add_p2p_connection(P2PInterface(), services=NODE_P2PMSG_LEAF)
        bare.sync_with_ping()
        assert_equal(node.getp2pmsginfo()["leaf_peers"], 0)
        assert_equal(node.sendp2pping(inbox, False), True)
        new.wait_until(lambda: new.message_count.get("p2pmsg", 0) >= 2, timeout=30)
        bare.sync_with_ping()
        assert_equal(bare.message_count.get("p2pmsg", 0), 0)

        # A v2 leaf receives fluff and is never a stem successor.
        self.log.info("A v2 leaf receives fluff only")
        leaf = node.add_p2p_connection(P2PInterface(), services=NODE_P2PMSG_LEAF | NODE_P2PMSG_V2)
        leaf.sync_with_ping()
        assert_equal(node.getp2pmsginfo()["leaf_peers"], 1)
        assert_equal(node.sendp2pping(inbox, False), True)
        leaf.wait_until(lambda: leaf.message_count.get("p2pmsg", 0) >= 1, timeout=30)
        # Stem has a relay to choose, so it is never the leaf that gets it.
        assert_equal(node.sendp2pping(inbox, True), True)
        new.wait_until(lambda: new.message_count.get("dp2pmsg", 0) >= 2, timeout=30)
        assert_equal(leaf.message_count.get("dp2pmsg", 0), 0)

        self.log.info("p2pmsg v2 service bit OK")


if __name__ == "__main__":
    P2PMsgV2BitTest(__file__).main()
