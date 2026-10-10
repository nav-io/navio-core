#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Token state survives a crash in the middle of a chainstate flush.

-dbcrashratio=1 with a one-byte -dbbatchsize makes the node exit on the
first partial batch of a flush, leaving the coins database marked as
between two tips. The next start replays the blocks in between: it rolls
back the blocks only on the old tip and rolls forward the ones on the new
tip. The tokens created and minted by those blocks must come out of the
replay exactly as they were before the crash.

Token writes themselves never land in a partial batch, so a flush whose
only oversized write is a token completes without a replay.
"""

import http.client

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlsctTokenReplayTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def token_state(self, token_ids):
        node = self.nodes[0]
        return node.getbestblockhash(), {t: node.gettoken(t) for t in token_ids}, node.listtokens()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", blsct=True)
        wallet = node.get_wallet_rpc("w")
        addr = wallet.getnewaddress(label="", address_type="blsct")
        self.generatetoblsctaddress(node, 101, addr)

        self.log.info("Create and mint a token in blocks that reach the database")
        flushed_token = wallet.createtoken({"name": "Flushed"}, 1000)['tokenId']
        nft = wallet.createnft({"name": "ReplayNft"}, 10)['tokenId']
        self.generatetoblsctaddress(node, 1, addr)
        wallet.minttoken(flushed_token, addr, 1)
        rolled_back = self.generatetoblsctaddress(node, 1, addr)[0]
        node.gettxoutsetinfo()  # forces a complete flush

        self.log.info("Restart crashing on the next flush")
        self.restart_node(0, extra_args=["-dbcrashratio=1", "-dbbatchsize=1"])
        node.loadwallet("w")
        wallet = node.get_wallet_rpc("w")

        self.log.info("Reorg away the flushed mint, then create and mint more")
        node.invalidateblock(rolled_back)
        self.generatetoblsctaddress(node, 1, addr)
        replayed_token = wallet.createtoken({"name": "Replayed"}, 1000)['tokenId']
        self.generatetoblsctaddress(node, 1, addr)
        wallet.minttoken(replayed_token, addr, 2)
        wallet.mintnft(nft, 1, addr, {"id": "1"})
        self.generatetoblsctaddress(node, 1, addr)

        token_ids = [flushed_token, nft, replayed_token]
        expected = self.token_state(token_ids)
        assert_equal(len(expected[2]), len(token_ids))

        self.log.info("Crash part way through flushing the chainstate")
        crashed = False
        try:
            node.gettxoutsetinfo()
        except (http.client.CannotSendRequest, OSError) as e:
            self.log.debug(f"node crashed as expected: {e!r}")
            crashed = True
        assert crashed, "gettxoutsetinfo returned without crashing the node"
        node.wait_until_stopped()

        self.log.info("Restart and replay the blocks between the two tips")
        with node.assert_debug_log(["Replaying blocks", "Rolling back", "Rolling forward"]):
            self.start_node(0, extra_args=[])
        assert_equal(self.token_state(token_ids), expected)

        self.log.info("A token write alone never cuts a partial batch")
        # The token's metadata alone exceeds -dbbatchsize while the coins
        # flushed with it do not, so the only write that could cut a partial
        # batch (and, with -dbcrashratio=1, crash) is the token's. Tokens are
        # not idempotent to replay, so they must stay in the final batch: the
        # flush has to complete, and the restart must find nothing to replay.
        self.restart_node(0, extra_args=["-dbcrashratio=1", "-dbbatchsize=40000"])
        node.loadwallet("w")
        wallet = node.get_wallet_rpc("w")
        big_token = wallet.createtoken({"name": "Big", "data": "x" * 60000}, 1000)['tokenId']
        self.generatetoblsctaddress(node, 1, addr)
        token_ids.append(big_token)
        expected = self.token_state(token_ids)
        assert_equal(len(expected[2]), len(token_ids))
        # The big token is the only token this flush changes, and the commit
        # log line counts token entries alongside the coins.
        with node.assert_debug_log(["Writing final batch", "and 1 changed tokens to coin database"], unexpected_msgs=["Writing partial batch", "Simulating a crash"]):
            node.gettxoutsetinfo()
        with node.assert_debug_log([], unexpected_msgs=["Replaying blocks"]):
            self.restart_node(0, extra_args=[])
        assert_equal(self.token_state(token_ids), expected)

if __name__ == '__main__':
    BlsctTokenReplayTest(__file__).main()
