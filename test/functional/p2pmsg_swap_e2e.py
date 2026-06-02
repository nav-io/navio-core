#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Funded two-node end-to-end RFQ atomic swap.

Node 1 (maker) holds a minted token and offers it for NAV. Node 0 (taker) holds
NAV and wants the token. The full bus flow runs across the wire:

  maker  setswapintent           offer token, receive NAV
  taker  requestquote            broadcast RFQ_REQ over the bus
  maker  (node matches inbound)  listpendingquoterequests surfaces it
  maker  replyquote              build + send the maker half (RFQ_QUOTE)
  taker  (quote arrives)         listquotes shows it
  taker  acceptquotewallet       build taker half, combine, broadcast swap

Then we mine and assert the swap confirms on-chain on both nodes.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PMsgSwapE2ETest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        args = ["-p2pmsg=1", "-p2pmsgpowbits=1"]
        self.extra_args = [args, args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def gb(self, node, addr, num, batch=4):
        r = num
        while r > 0:
            t = min(batch, r)
            self.generatetoblsctaddress(node, t, addr)
            r -= t

    def run_test(self):
        taker_n, maker_n = self.nodes[0], self.nodes[1]
        self.connect_nodes(0, 1)

        taker_n.createwallet(wallet_name="taker", blsct=True)
        maker_n.createwallet(wallet_name="maker", blsct=True)
        taker = taker_n.get_wallet_rpc("taker")
        maker = maker_n.get_wallet_rpc("maker")
        taker_addr = taker.getnewaddress(label="", address_type="blsct")
        maker_addr = maker.getnewaddress(label="", address_type="blsct")

        # Fund the taker with NAV.
        self.gb(taker_n, taker_addr, 110)
        # Fund the maker with NAV (for token + swap fees) and mint a token.
        self.gb(maker_n, maker_addr, 110)
        self.sync_all()
        token = maker.createtoken({"name": "SWAPTOK"}, 1000)
        tid = token["tokenId"]
        self.gb(maker_n, maker_addr, 1)
        maker.minttoken(tid, maker_addr, 5)
        self.gb(maker_n, maker_addr, 2)
        self.sync_all()
        assert maker.gettokenbalance(tid) >= 5, maker.gettokenbalance(tid)

        one = 100000000  # 1 token / 1 NAV in base units

        # Maker offers the token for NAV (price 0.1 NAV/token), sizes 1..5 tokens.
        maker.setswapintent(tid, "", one, 5 * one, 10000000, 1893456000)

        # Taker asks to buy 1 token paying NAV. Broadcast over the bus.
        res = taker.requestquote(tid, "", one, 1893456000)
        uuid = res["uuid"]

        # Maker's node matches the inbound request; build + send the quote.
        self.wait_until(lambda: len(maker.listpendingquoterequests()) >= 1, timeout=30)
        assert_equal(maker.listpendingquoterequests()[0]["uuid"], uuid)
        maker.replyquote(uuid)

        # Taker collects the quote and accepts it.
        self.wait_until(lambda: len(taker.listquotes(uuid)) >= 1, timeout=30)
        quote = taker.listquotes(uuid)[0]
        txid = taker.acceptquotewallet(uuid, quote["quote_id"])
        self.log.info("swap txid=%s" % txid)

        # Confirm on-chain.
        self.wait_until(lambda: txid in taker_n.getrawmempool(), timeout=20)
        blocks = self.generatetoblsctaddress(taker_n, 1, taker_addr)
        self.sync_all()
        blk = taker_n.getblock(blocks[0])
        assert txid in blk["tx"], "swap not in the mined block"

        self.log.info("two-node RFQ atomic swap confirmed on-chain OK")


if __name__ == "__main__":
    P2PMsgSwapE2ETest(__file__).main()
