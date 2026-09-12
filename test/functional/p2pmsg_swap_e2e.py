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
        # Mint in two separate transactions so the maker's token balance is
        # SPLIT across two coins (3 + 2). The maker half must then gather more
        # than one input to fund a 5-token quote: input gathering that stops
        # after a single candidate (the nAmountLimit=0 bug) fails here with
        # "Not enough of the pay token".
        maker.minttoken(tid, maker_addr, 3)
        self.gb(maker_n, maker_addr, 1)
        maker.minttoken(tid, maker_addr, 2)
        self.gb(maker_n, maker_addr, 2)
        self.sync_all()
        assert maker.gettokenbalance(tid) >= 5, maker.gettokenbalance(tid)

        one = 100000000  # 1 token / 1 NAV in base units

        # Maker offers the token for NAV (price 0.1 NAV/token), sizes 1..5 tokens.
        maker.setswapintent(tid, "", one, 5 * one, 10000000, 1893456000)

        # Taker asks to buy 5 tokens paying NAV — the full split balance, so
        # the maker's quote half must combine both minted coins.
        res = taker.requestquote(tid, "", 5 * one, 1893456000)
        uuid = res["uuid"]

        # Maker's node matches the inbound request; build + send the quote.
        self.wait_until(lambda: len(maker.listpendingquoterequests()) >= 1, timeout=30)
        assert_equal(maker.listpendingquoterequests()[0]["uuid"], uuid)
        maker.replyquote(uuid)

        # Taker collects the quote and accepts it.
        self.wait_until(lambda: len(taker.listquotes(uuid)) >= 1, timeout=30)
        quote = taker.listquotes(uuid)[0]
        # Slippage bounds: accept exactly the quoted terms (max_pay=sell_cost,
        # min_recv=fill). A worse quote would be rejected by these bounds.
        txid = taker.acceptquotewallet(uuid, quote["quote_id"],
                                       quote["sell_cost"], quote["fill"])
        self.log.info("swap txid=%s" % txid)

        # Confirm on-chain.
        self.wait_until(lambda: txid in taker_n.getrawmempool(), timeout=20)

        # Pin the split: the maker half must have combined BOTH token coins
        # (plus a NAV fee coin), the taker at least one NAV coin — so the
        # combined swap carries >= 4 inputs. Without this, coin-selection
        # changes (e.g. minttoken merging its own change) could quietly turn
        # the split-balance setup above into a single-coin swap that covers
        # nothing.
        swap_vin = len(taker_n.getrawtransaction(txid, True)["vin"])
        assert swap_vin >= 4, f"expected a multi-input swap, got {swap_vin} inputs"

        blocks = self.generatetoblsctaddress(taker_n, 1, taker_addr)
        self.sync_all()
        blk = taker_n.getblock(blocks[0])
        assert txid in blk["tx"], "swap not in the mined block"

        self.log.info("two-node RFQ atomic swap confirmed on-chain OK")

        # NAV-pay fee headroom: an offer of (almost) a whole NAV coin must
        # still build — the fee comes on top of pay_amount from the same
        # token, so the maker needs a second coin for it. 6 NAV split 5 + 1,
        # offering 5, failed with "failed to build order half" when input
        # gathering stopped at the bare requirement.
        maker2_n = maker_n
        maker2_n.createwallet(wallet_name="maker2", blsct=True)
        maker2 = maker2_n.get_wallet_rpc("maker2")
        maker2_addr = maker2.getnewaddress(label="", address_type="blsct")
        maker.sendtoblsctaddress(maker2_addr, 5)
        self.gb(maker_n, maker_addr, 1)
        maker.sendtoblsctaddress(maker2_addr, 1)
        self.gb(maker_n, maker_addr, 2)
        self.sync_all()
        assert_equal(maker2.getbalance(), 6)

        # NB: broadcastorder amounts are RPCArg::Type::AMOUNT (decimal), not
        # raw base units like requestquote's size.
        res = maker2.broadcastorder("", 5.0, tid, 1, 1893456000)
        assert res, "NAV-pay order across a 5+1 split failed to build"
        self.log.info("NAV-pay order with fee headroom across split coins OK")


if __name__ == "__main__":
    P2PMsgSwapE2ETest(__file__).main()
