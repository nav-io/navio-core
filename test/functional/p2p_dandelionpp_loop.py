#!/usr/bin/env python3
# Copyright (c) 2018 Bradley Denby
# Copyright (c) 2023-2023 The Navio Core developers
# Distributed under the MIT software license. See the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test transaction behaviors under the Dandelion spreading policy

NOTE: check link for basis of this test:
https://github.com/digibyte/digibyte/blob/master/test/functional/p2p_dandelion.py

Loop behavior:
    Stem:  0 --> 1 --> 2 --> 0 where each node supports Dandelion++
    Probe: TestNode --> 0
    For nodes to sync mempools after creating the tx then
    Assert that Node 0 does not reply with tx since it's still
    under embargo and Probe is not a stem route
"""

from test_framework.messages import (
        CInv,
        msg_getdata,
        msg_mempool,
        MSG_WTX,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet


class DandelionLoopTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [
            ["-dandelion", "-whitelist=all@127.0.0.1"],
            ["-dandelion=false", "-whitelist=all@127.0.0.1"],
            ["-dandelion=false", "-whitelist=all@127.0.0.1"],
        ]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(2, 0)

    def run_test(self):
        self.log.info("Starting dandelion tests")

        self.log.info("Setting up wallet")
        wallet = MiniWallet(self.nodes[0])

        self.log.info("Sync nodes")
        self.sync_all()

        self.log.info("Adding decoy peers to reduce stem selection probability")
        decoys = [self.nodes[0].add_p2p_connection(P2PInterface()) for _ in range(9)]

        self.log.info("Create the tx on node 0")
        tx = wallet.send_self_transfer(from_node=self.nodes[0])
        txid = int(tx["wtxid"], 16)
        self.log.info("Sent tx {}".format(txid))

        self.log.info("Wait for node 0 to accept tx")
        self.wait_until(lambda: tx["txid"] in self.nodes[0].getrawmempool())

        for peer in decoys:
            self.log.info("Send mempool request to check embargo state")
            peer.send_and_ping(msg_mempool())

            msg = msg_getdata()
            msg.inv.append(CInv(t=MSG_WTX, h=txid))
            peer.send_and_ping(msg)
            self.log.info("Sending msg_getdata: CInv({},{})".format(MSG_WTX, txid))

            if peer.last_message.get("notfound"):
                self.log.info("Peer is non-stem, embargo working correctly")
                return

        self.log.error("Test failed - all peers were stem peers")
        assert False


if __name__ == "__main__":
    DandelionLoopTest().main()
