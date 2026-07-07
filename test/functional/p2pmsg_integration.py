#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Integration coverage for the wired p2p-messaging surface.

Exercises, across two connected nodes with -p2pmsg enabled:
  - getp2pmsginfo / inbox keys,
  - cross-wire encrypted PING echo (fluff + stem),
  - maker intent RPCs (set / list / clear),
  - standing-order cache RPC,
  - that an undecryptable message does not increment a peer's PING counter,
  - that nodes stay connected throughout (no DoS disconnect on valid traffic).
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PMsgIntegrationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        args = ["-p2pmsg=1", "-p2pmsgpowbits=1"]
        self.extra_args = [args, args]

    def run_test(self):
        a, b = self.nodes[0], self.nodes[1]
        self.connect_nodes(0, 1)

        info_a = a.getp2pmsginfo()
        info_b = b.getp2pmsginfo()
        assert_equal(info_a["enabled"], True)
        assert_equal(info_b["enabled"], True)
        a_inbox, b_inbox = info_a["inbox_pubkey"], info_b["inbox_pubkey"]
        assert a_inbox != b_inbox

        # --- PING echo, fluff then stem ---
        self.log.info("cross-wire PING echo")
        assert_equal(a.sendp2pping(b_inbox, False), True)
        self.wait_until(lambda: b.getp2pmsginfo()["pings_received"] >= 1, timeout=20)
        before = b.getp2pmsginfo()["pings_received"]
        assert_equal(a.sendp2pping(b_inbox, True), True)
        self.wait_until(lambda: b.getp2pmsginfo()["pings_received"] >= before + 1, timeout=20)

        # --- Undecryptable PING (to A's own key) must not bump B; fence with a
        # decryptable one so we know the bad message was processed first. ---
        self.log.info("undecryptable PING is dropped silently")
        b_count = b.getp2pmsginfo()["pings_received"]
        assert_equal(a.sendp2pping(a_inbox, False), True)
        assert_equal(a.sendp2pping(b_inbox, False), True)
        self.wait_until(lambda: b.getp2pmsginfo()["pings_received"] >= b_count + 1, timeout=20)
        assert_equal(b.getp2pmsginfo()["pings_received"], b_count + 1)

        # --- Maker intents ---
        self.log.info("maker intent RPCs")
        assert_equal(b.listswapintents(), [])
        iid = b.setswapintent("", "01" * 32, 100, 1000, 100000000, 1893456000)
        intents = b.listswapintents()
        assert_equal(len(intents), 1)
        assert_equal(intents[0]["min_size"], 100)
        assert_equal(intents[0]["max_size"], 1000)
        assert_equal(b.clearswapintent(iid), True)
        assert_equal(b.listswapintents(), [])

        # --- Standing-order cache ---
        self.log.info("standing-order cache RPC")
        orders = b.listorders()
        assert_equal(orders["enabled"], True)
        assert_equal(orders["count"], 0)

        # --- Both nodes still connected after all the valid traffic (valid
        # p2pmsg must not trigger a DoS disconnect). ---
        assert len(a.getpeerinfo()) >= 1
        assert len(b.getpeerinfo()) >= 1

        self.log.info("p2pmsg integration OK")


if __name__ == "__main__":
    P2PMsgIntegrationTest(__file__).main()
