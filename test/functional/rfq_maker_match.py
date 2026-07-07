#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Maker-side RFQ matching over the wire.

A maker configures a local swap intent. A taker broadcasts an RFQ request over
the bus. The maker's node decrypts it (broadcast key), matches it against the
intent, and queues it as a pending quote request that the wallet can answer with
replyquote. We assert the pending request surfaces on the maker with the right
fill / sell_cost / reply_key.
"""

from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class RfqMakerMatchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        args = ["-p2pmsg=1", "-p2pmsgpowbits=1"]
        self.extra_args = [args, args]

    def run_test(self):
        taker, maker = self.nodes
        self.connect_nodes(0, 1)

        TOKA = "01" * 32
        # Maker: pays TOKA, wants NAV, price 0.1 NAV/TOKA (1e7/1e8), sizes 100..1000.
        maker.setswapintent(TOKA, "", 100, 1000, 10000000, 1893456000)
        assert_equal(maker.listpendingquoterequests(), [])

        # Taker: buy TOKA, sell NAV, size 500.
        res = taker.requestquote(TOKA, "", 500, 1893456000)
        uuid = res["uuid"]

        # The maker should surface the matched request to answer.
        self.wait_until(lambda: len(maker.listpendingquoterequests()) >= 1, timeout=20)
        pend = maker.listpendingquoterequests()
        assert_equal(len(pend), 1)
        p = pend[0]
        assert_equal(p["uuid"], uuid)
        assert_equal(p["fill"], 500)          # deliver 500 TOKA
        assert_equal(p["sell_cost"], 50)      # charge 500 * 0.1 = 50 NAV
        assert_equal(p["reply_key"], res["reply_key"])

        # The taker, which did not configure an intent, has nothing pending.
        assert_equal(taker.listpendingquoterequests(), [])

        self.log.info("maker RFQ match over the wire OK")

        # Light-maker path: answer the pending request with sendquote, supplying
        # an externally built half. The node wraps + signs + encrypts it; the
        # taker's node must collect it under the open uuid. (A syntactically
        # valid tx is enough here — combine/verify is exercised in the e2e test.)
        half = CTransaction()
        half.vin.append(CTxIn(COutPoint(1)))
        half.vout.append(CTxOut(0, b""))
        half_hex = half.serialize().hex()

        quote_id = maker.sendquote(uuid, p["reply_key"], half_hex, TOKA, "", 500, 50, 1893456000)

        # The pending match is consumed one-shot on the maker.
        assert_equal(maker.listpendingquoterequests(), [])

        # The taker collects the encrypted quote over the wire.
        self.wait_until(lambda: len(taker.listquotes(uuid)) >= 1, timeout=20)
        quotes = taker.listquotes(uuid)
        assert_equal(len(quotes), 1)
        assert_equal(quotes[0]["quote_id"], quote_id)
        assert_equal(quotes[0]["fill"], 500)
        assert_equal(quotes[0]["sell_cost"], 50)

        self.log.info("light-maker sendquote over the wire OK")

        # Light-maker standing order: sendorder caches locally and broadcasts.
        order_half = CTransaction()
        order_half.vin.append(CTxIn(COutPoint(2)))
        order_half.vout.append(CTxOut(0, b""))
        maker.sendorder(order_half.serialize().hex(), TOKA, 500, "", 50, 1893456000)

        assert_equal(maker.listorders()["count"], 1)
        # Peers cache the broadcast order too.
        self.wait_until(lambda: taker.listorders()["count"] >= 1, timeout=20)

        self.log.info("light-maker sendorder over the wire OK")


if __name__ == "__main__":
    RfqMakerMatchTest(__file__).main()
