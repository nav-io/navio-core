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

from decimal import Decimal
import time

from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

# rfq::ORDER_PRUNE_INTERVAL (src/rfq/order_cache.h), in seconds.
ORDER_PRUNE_INTERVAL = 60


def order_half_hex(outpoint):
    """A syntactically valid standing-order half spending `outpoint`."""
    half = CTransaction()
    half.vin.append(CTxIn(COutPoint(outpoint)))
    half.vout.append(CTxOut(0, b""))
    return half.serialize().hex()


class RfqMakerMatchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        args = ["-p2pmsg=1", "-p2pmsgpowbits=1"]
        # One decrypt worker on the maker, so it handles RFQ requests strictly
        # in arrival order (see test_nft_token_ids).
        self.extra_args = [args, args + ["-onionworkers=1"]]

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

        # A quote answers the request's reply key and nothing else. A second
        # valid, signed quote for the same open request, encrypted to the
        # taker's published inbox key instead, must be dropped before it
        # reaches the quote set (AddQuote would otherwise take it: the uuid is
        # open and the pair matches).
        taker_inbox = taker.getp2pmsginfo()["inbox_pubkey"]
        with taker.assert_debug_log(["p2pmsg: dropping kind 5 addressed to an inbox key"], timeout=20):
            maker.sendquote(uuid, taker_inbox, half_hex, TOKA, "", 500, 50, 1893456000)
        assert_equal([q["quote_id"] for q in taker.listquotes(uuid)], [quote_id])

        self.log.info("light-maker sendquote over the wire OK")

        # Light-maker standing order: sendorder caches locally and broadcasts.
        order_half = CTransaction()
        order_half.vin.append(CTxIn(COutPoint(2)))
        order_half.vout.append(CTxOut(0, b""))
        order_id = maker.sendorder(order_half.serialize().hex(), TOKA, 500, "", 50, 1893456000)

        assert_equal(maker.listorders()["count"], 1)
        # Non-verbose output is unchanged (no order list).
        assert "orders" not in maker.listorders()
        # Peers cache the broadcast order too.
        self.wait_until(lambda: taker.listorders()["count"] >= 1, timeout=20)

        # Verbose listing on the receiving peer exposes exactly the public
        # ORDER_ANN fields of the cached order.
        listed = taker.listorders(True)
        assert_equal(listed["count"], 1)
        assert_equal(len(listed["orders"]), 1)
        o = listed["orders"][0]
        assert_equal(o["quote_id"], order_id)
        assert_equal(o["buy"], TOKA)
        assert_equal(o["sell"], "00" * 32)
        assert_equal(o["fill"], 500)
        assert_equal(o["sell_cost"], 50)
        assert_equal(o["price"], Decimal("0.1"))
        assert_equal(o["order_expiry"], 1893456000)
        assert o["received"] <= o["effective_expiry"] <= 1893456000
        # The 14-day cap binds for this order (expiry is far out), so the two
        # node-local fields are rigidly related; emitting either one wrong
        # (e.g. effective_expiry = order_expiry, or received = effective_expiry)
        # breaks this equality.
        assert_equal(o["effective_expiry"], o["received"] + 14 * 86400)
        assert_equal(o["half_txid"], order_half.rehash())
        assert_equal(o["inputs"], ["%064x" % 2])
        assert_equal(len(o["maker_pubkey"]), 96)
        # The maker's own cache shows the same wire fields; only the local
        # receive time (and hence the effective expiry) may differ.
        local = dict(maker.listorders(True)["orders"][0])
        wire = dict(o)
        for k in ("received", "effective_expiry"):
            del local[k], wire[k]
        assert_equal(local, wire)

        self.log.info("light-maker sendorder over the wire OK")

        self.test_listorders_paging(maker, TOKA)
        self.test_expired_orders_pruned(maker, TOKA)
        self.test_nft_token_ids(taker, maker, TOKA)

    def test_listorders_paging(self, maker, token):
        self.log.info("listorders count/skip page through the sorted orders")
        # Expiries both before and after the order already cached, so paging
        # must follow the sort rather than insertion order.
        for i, expiry in enumerate([1893456000 + 2, 1893456000 - 1, 1893456000 + 1]):
            maker.sendorder(order_half_hex(10 + i), token, 500, "", 50, expiry)
        full = maker.listorders(True)
        orders = full["orders"]
        assert_equal(len(orders), 4)
        assert_equal([o["order_expiry"] for o in orders], [1893456000 - 1, 1893456000, 1893456000 + 1, 1893456000 + 2])

        assert_equal(maker.listorders(True, 2)["orders"], orders[:2])
        assert_equal(maker.listorders(True, 2, 1)["orders"], orders[1:3])
        assert_equal(maker.listorders(True, 10, 3)["orders"], orders[3:])
        assert_equal(maker.listorders(True, 0)["orders"], [])
        assert_equal(maker.listorders(True, 1, 4)["orders"], [])
        assert_equal(maker.listorders(True, None, 2)["orders"], orders[2:])
        # Paging narrows the list only; the totals still describe the cache.
        page = maker.listorders(True, 1, 1)
        assert_equal((page["count"], page["bytes"]), (full["count"], full["bytes"]))
        assert_raises_rpc_error(-8, "Negative count", maker.listorders, True, -1)
        assert_raises_rpc_error(-8, "Negative skip", maker.listorders, True, 1, -1)

    def test_expired_orders_pruned(self, maker, token):
        self.log.info("expired standing orders are pruned without an RFQ")
        # Nothing on this node scans the cache for an RFQ, so only the
        # scheduled prune can drop the expired order from the raw count.
        now = int(time.time())
        maker.setmocktime(now)
        before = maker.listorders()["count"]
        expiring = maker.sendorder(order_half_hex(3), token, 500, "", 50, now + 100)
        assert_equal(maker.listorders()["count"], before + 1)

        maker.setmocktime(now + 101)
        # Expired: hidden from the listing at once, but only a prune drops it
        # from the raw count.
        assert expiring not in [o["quote_id"] for o in maker.listorders(True)["orders"]]

        maker.mockscheduler(ORDER_PRUNE_INTERVAL)
        self.wait_until(lambda: maker.listorders()["count"] == before, timeout=10)
        maker.setmocktime(0)

    def test_nft_token_ids(self, taker, maker, token):
        self.log.info("an NFT token id (<hex>#<subid>) round-trips through every RFQ RPC")
        nft = token + "#7"
        expiry = 1893456000
        order_id = maker.sendorder(order_half_hex(20), nft, 500, "", 50, expiry)
        self.wait_until(lambda: order_id in [o["quote_id"] for o in taker.listorders(True)["orders"]], timeout=20)
        listed = next(o for o in taker.listorders(True)["orders"] if o["quote_id"] == order_id)
        assert_equal(listed["buy"], nft)
        # From here on use the listed spelling verbatim: what listorders prints
        # must be accepted back as input.
        nft = listed["buy"]

        # The subid travels with the request: the maker's intent on the bare
        # token (from run_test) must not answer an NFT request. An unmatched
        # request leaves no trace on the maker, so the bare-token request sent
        # after it is the sync point. That holds only because the taker emits
        # both on one connection in call order and the maker's single worker
        # (-onionworkers=1) dispatches its FIFO ring one job at a time: once
        # the bare request is pending, the NFT one has been fully handled. With
        # more workers the NFT request could still be in flight here.
        nft_uuid = taker.requestquote(nft, "", 500, expiry)["uuid"]
        bare_uuid = taker.requestquote(token, "", 500, expiry)["uuid"]
        self.wait_until(lambda: bare_uuid in [p["uuid"] for p in maker.listpendingquoterequests()], timeout=20)
        assert nft_uuid not in [p["uuid"] for p in maker.listpendingquoterequests()]

        intent_id = maker.setswapintent(nft, "", 100, 1000, 10000000, expiry)
        # The run_test intent is on the fungible token, which prints exactly as
        # before (no suffix).
        assert_equal(sorted((i["id"] == intent_id, i["token_in"], i["token_out"]) for i in maker.listswapintents()),
                     [(False, token, "00" * 32), (True, nft, "00" * 32)])

        uuid = taker.requestquote(nft, "", 500, expiry)["uuid"]
        self.wait_until(lambda: uuid in [p["uuid"] for p in maker.listpendingquoterequests()], timeout=20)
        p = next(p for p in maker.listpendingquoterequests() if p["uuid"] == uuid)
        assert_equal((p["buy_token"], p["sell_token"]), (nft, "00" * 32))
        bare = next(p for p in maker.listpendingquoterequests() if p["uuid"] == bare_uuid)
        assert_equal((bare["buy_token"], bare["sell_token"]), (token, "00" * 32))

        # The taker only collects a quote whose pair equals the open request's,
        # so this lands only if sendquote parsed the NFT id intact.
        quote_id = maker.sendquote(uuid, p["reply_key"], order_half_hex(21), nft, "", 500, 50, expiry)
        self.wait_until(lambda: len(taker.listquotes(uuid)) >= 1, timeout=20)
        quotes = taker.listquotes(uuid)
        assert_equal([(q["quote_id"], q["buy"]) for q in quotes], [(quote_id, nft)])

        self.log.info("malformed token ids are rejected by every RFQ RPC")
        bad_ids = [
            token + "#",                       # empty subid
            token + "#-1",                     # sign
            token + "#+7",                     # sign
            token + "#0x7",                    # hex subid
            token + "#07",                     # second spelling of #7
            token + "# 7",                     # whitespace
            token + "#18446744073709551616",   # overflows uint64
            token + "#18446744073709551615",   # fungible sentinel: would alias the bare token
            "00" * 32 + "#1",                  # NAV has no NFTs
            token[:-2] + "#7",                 # short token hash
        ]
        for bad in bad_ids:
            assert_raises_rpc_error(-8, f"token_in must be a 64-hex token id, followed by #<subid> for an NFT, or empty for NAV (not '{bad}')",
                                    maker.setswapintent, bad, "", 100, 1000, 10000000, expiry)
        bad = token + "#"
        assert_raises_rpc_error(-8, "token_out must be a 64-hex token id", maker.setswapintent, "", bad, 100, 1000, 10000000, expiry)
        assert_raises_rpc_error(-8, "buy_token must be a 64-hex token id", taker.requestquote, bad, "", 500, expiry)
        assert_raises_rpc_error(-8, "sell_token must be a 64-hex token id", taker.requestquote, "", bad, 500, expiry)
        assert_raises_rpc_error(-8, "buy_token must be a 64-hex token id", maker.sendquote, uuid, p["reply_key"], order_half_hex(22), bad, "", 500, 50, expiry)
        assert_raises_rpc_error(-8, "sell_token must be a 64-hex token id", maker.sendquote, uuid, p["reply_key"], order_half_hex(22), "", bad, 500, 50, expiry)
        assert_raises_rpc_error(-8, "offer_token must be a 64-hex token id", maker.sendorder, order_half_hex(22), bad, 500, "", 50, expiry)
        assert_raises_rpc_error(-8, "want_token must be a 64-hex token id", maker.sendorder, order_half_hex(22), "", 500, bad, 50, expiry)


if __name__ == "__main__":
    RfqMakerMatchTest(__file__).main()
