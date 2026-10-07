#!/usr/bin/env python3
# Copyright (c) 2018 Bradley Denby
# Copyright (c) 2023-2023 The Navio Core developers
# Distributed under the MIT software license. See the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test transaction behaviors under the Dandelion spreading policy

NOTE: check link for basis of this test:
https://github.com/digibyte/digibyte/blob/master/test/functional/p2p_dandelion.py

Resistance to active probing:
   Probe: TestNode --> 0
   Node0 generates a Dandelion++ transaction "tx"
   TestNode immediately sends getdata for tx to Node0
   Assert that Node 0 does not reply with tx
"""

from test_framework.messages import (
        CInv,
        msg_getdata,
        msg_mempool,
        MSG_OUTPUT_HASH,
        MSG_WITNESS_TX,
        MSG_WTX,
        MSG_DWTX,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class DandelionProbingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-dandelion", "-whitelist=all@127.0.0.1"]]

    def run_test(self):
        # There is a low probability that these tests will fail even if the
        # implementation is correct. Thus, these tests are repeated upon
        # failure. A true bug will result in repeated failures.
        self.log.info("Starting dandelion tests")

        self.log.info("Setting up wallet")
        wallet = MiniWallet(self.nodes[0])

        self.log.info("Create the tx on node 1")
        tx = wallet.send_self_transfer(from_node=self.nodes[0])
        txid = int(tx['wtxid'], 16)
        self.log.info("Sent tx with {}".format(txid))

        self.log.info("Adding P2PInterface")
        self.nodes[0].add_p2p_connection(P2PInterface())  # Fake dandelion peer
        peer = self.nodes[0].add_p2p_connection(P2PInterface()) # Probing peer

        for tx_type in [MSG_WTX, MSG_DWTX]:
            # Create and send msg_mempool to node to bypass mempool request
            # security
            peer.send_and_ping(msg_mempool())

            # Create and send msg_getdata for the tx
            msg = msg_getdata()
            msg.inv.append(CInv(t=tx_type, h=txid))
            peer.send_and_ping(msg)
            self.log.info("Sending msg_getdata: CInv({}, {})".format(tx_type, txid))

            assert peer.last_message.get("notfound")

        # By output hash, both as MSG_WITNESS_TX and as the MSG_OUTPUT_HASH
        # still served to #489-era nodes that send it.
        self.log.info("Requesting the tx by one of its output hashes applies the same rule")
        output_hash = tx["tx"].vout[0].hash()
        for inv_type in [MSG_WITNESS_TX, MSG_OUTPUT_HASH]:
            peer.last_message.pop("notfound", None)
            peer.send_and_ping(msg_getdata([CInv(t=inv_type, h=output_hash)]))
            notfound = peer.last_message.get("notfound")
            assert notfound
            assert_equal([(inv.type, inv.hash) for inv in notfound.vec], [(inv_type, output_hash)])
            assert "tx" not in peer.last_message
            assert "dtx" not in peer.last_message

        # The other half of the rule: the peer the tx is stemmed to IS served it
        # by output hash, as dtx (still stem phase), not as a plain tx.
        # Restarting drops every connection, so the one peer connected next is
        # the only route the stem shuffle can pick.
        self.log.info("The stem peer is served the tx as dtx when it asks by output hash")
        self.generate(self.nodes[0], 1)
        self.restart_node(0)
        # Wait for the peer to be picked as the stem route before sending the
        # tx. A shuffle that runs before the peer's tx relay state exists finds
        # nothing and backs off for 10 seconds; the embargo can run out first,
        # and the tx would then be announced as MSG_WTX instead.
        with self.nodes[0].assert_debug_log(["Shuffled stem peers (found=1"], timeout=15):
            stem_peer = self.nodes[0].add_p2p_connection(P2PInterface())
        stem_tx = wallet.send_self_transfer(from_node=self.nodes[0])
        stem_wtxid = int(stem_tx["wtxid"], 16)
        stem_peer.wait_until(lambda: any(
            inv.type == MSG_DWTX and inv.hash == stem_wtxid
            for inv in stem_peer.last_message["inv"].inv) if "inv" in stem_peer.last_message else False)

        # P2PInterface.on_inv already fetched the tx by wtxid; drop that dtx so
        # the one checked below can only be the reply to the output-hash request.
        stem_peer.sync_with_ping()
        with p2p_lock:
            stem_peer.last_message.pop("dtx", None)

        stem_output_hash = stem_tx["tx"].vout[0].hash()
        for inv_type in [MSG_WITNESS_TX, MSG_OUTPUT_HASH]:
            stem_peer.last_message.pop("dtx", None)
            stem_peer.send_and_ping(msg_getdata([CInv(t=inv_type, h=stem_output_hash)]))
            assert "notfound" not in stem_peer.last_message
            assert "tx" not in stem_peer.last_message
            assert_equal(stem_peer.last_message["dtx"].tx.getwtxid(), stem_tx["wtxid"])


if __name__ == "__main__":
    DandelionProbingTest(__file__).main()
