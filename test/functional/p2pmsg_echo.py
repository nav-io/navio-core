#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Encrypted p2p messaging: PING echo across the wire.

Two nodes with -p2pmsg enabled. Node 0 encrypts a PING to node 1's inbox
session key and broadcasts it; node 1 decrypts on its worker pool and bumps
its PING counter. Exercises the full path: wire dispatch -> net-thread PoW/
replay gate -> worker decrypt -> handler. PoW difficulty is set to 1 bit so
the test does not burn CPU.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PMsgEchoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        args = ["-p2pmsg=1", "-p2pmsgpowbits=1"]
        self.extra_args = [args, args]

    def run_test(self):
        a, b = self.nodes[0], self.nodes[1]

        info_a = a.getp2pmsginfo()
        info_b = b.getp2pmsginfo()
        assert_equal(info_a["enabled"], True)
        assert_equal(info_b["enabled"], True)
        assert "inbox_pubkey" in info_b
        assert_equal(info_b["pings_received"], 0)

        self.connect_nodes(0, 1)

        b_inbox = info_b["inbox_pubkey"]
        a_inbox = info_a["inbox_pubkey"]

        # Send a PING from A to B's inbox, fluff phase (deterministic delivery).
        self.log.info("A -> B PING (fluff)")
        assert_equal(a.sendp2pping(b_inbox, False), True)
        self.wait_until(lambda: b.getp2pmsginfo()["pings_received"] >= 1, timeout=20)

        # Stem phase: may fluff onward, but B is a direct peer so it still lands.
        self.log.info("A -> B PING (stem)")
        before = b.getp2pmsginfo()["pings_received"]
        assert_equal(a.sendp2pping(b_inbox, True), True)
        self.wait_until(lambda: b.getp2pmsginfo()["pings_received"] >= before + 1, timeout=20)

        # A PING encrypted to A's own key, broadcast to peers, reaches B but B
        # cannot decrypt it -> B's counter must stay flat. (Broadcast goes to
        # peers only, so it never loops back to A either.)
        self.log.info("A -> B PING encrypted to A's key (B must not decrypt)")
        b_count = b.getp2pmsginfo()["pings_received"]
        assert_equal(a.sendp2pping(a_inbox, False), True)
        # Land a second decryptable PING to B as a fence: once B processes it,
        # the undecryptable one ahead of it has already been handled too.
        assert_equal(a.sendp2pping(b_inbox, False), True)
        self.wait_until(lambda: b.getp2pmsginfo()["pings_received"] >= b_count + 1, timeout=20)
        assert_equal(b.getp2pmsginfo()["pings_received"], b_count + 1)

        self.log.info("p2pmsg echo OK")


if __name__ == "__main__":
    P2PMsgEchoTest(__file__).main()
