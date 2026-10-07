#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test compact block relay of BLSCT aggregate blocks (sendcmpct version 3).

A BLSCT block holding several user transactions carries a single aggregate
built from them, which is never in any mempool. Peers that announced
sendcmpct version 3 get a "cmpctaggblk" listing the aggregate's components
instead, rebuild the aggregate from their mempool and only fetch missing
components ("getaggblktxn"/"aggblocktxn"), never the whole aggregate.

Topology: node1 -> node0 <- node2, node0 mines. node2 runs -blocksonly and
so does not announce version 3.

Checks:
- node1 reconstructs an aggregate block from its mempool with no round trip;
- node1, missing some components, fetches exactly those and not the block;
- node0 never sends a cmpctaggblk to node2, which still syncs.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
)

UTXO_AMOUNT = Decimal("10.01")
SEND_AMOUNT = Decimal("10")


class CompactAggregateBlocksTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 3
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [[], [], ["-blocksonly"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 0)

    def mine(self, n=1):
        hashes = []
        for _ in range(n):
            hashes.extend(self.generatetoblsctaddress(self.nodes[0], 1, self.miner_addr, sync_fun=self.sync_blocks))
        return hashes

    def send(self, count):
        for _ in range(count):
            self.sender.sendtoblsctaddress(self.recv_addr, SEND_AMOUNT)

    def per_msg(self, node, other, direction):
        """bytes{sent,recv}_per_msg of `node`'s connection with `other` (one of them connected to the other)."""
        for info in node.getpeerinfo():
            if info["addr"] == f"127.0.0.1:{p2p_port(other.index)}":
                return info[f"bytes{direction}_per_msg"]
        # Inbound connection: match the port `other` connected from.
        [outbound] = [i for i in other.getpeerinfo() if i["addr"] == f"127.0.0.1:{p2p_port(node.index)}"]
        [info] = [i for i in node.getpeerinfo() if i["addr"] == outbound["addrbind"]]
        return info[f"bytes{direction}_per_msg"]

    def mine_aggregate_block(self):
        """Mine one block on node0 holding node0's whole mempool as one aggregate."""
        assert len(self.nodes[0].getrawmempool()) >= 2
        block_hash = self.mine()[0]
        assert_equal(len(self.nodes[0].getblock(block_hash)["tx"]), 2)
        assert_equal(self.nodes[0].getrawmempool(), [])
        return block_hash

    def run_test(self):
        node0, node1, _ = self.nodes
        node0.createwallet(wallet_name="funder", blsct=True)
        node0.createwallet(wallet_name="sender", blsct=True)
        node1.createwallet(wallet_name="receiver", blsct=True)
        funder = node0.get_wallet_rpc("funder")
        self.sender = node0.get_wallet_rpc("sender")
        self.miner_addr = funder.getnewaddress(label="", address_type="blsct")
        self.recv_addr = node1.get_wallet_rpc("receiver").getnewaddress(label="", address_type="blsct")

        self.mine(110)
        # Independent confirmed UTXOs, so the sends below are siblings.
        for _ in range(6):
            funder.sendtoblsctaddress(self.sender.getnewaddress(label="", address_type="blsct"), UTXO_AMOUNT)
        self.mine()

        self.test_reconstruct_from_mempool()
        self.test_fetch_missing_components()
        self.test_version2_peer()

    def test_reconstruct_from_mempool(self):
        self.log.info("A peer with every component in its mempool rebuilds the aggregate without a round trip")
        node0, node1, _ = self.nodes
        self.send(3)
        self.sync_mempools(self.nodes[:2])
        recv_before = self.per_msg(node1, node0, "recv")
        with node1.assert_debug_log(expected_msgs=["Rebuilt aggregate transaction of block", "from 3 components"]):
            block_hash = self.mine_aggregate_block()
        assert_equal(node1.getbestblockhash(), block_hash)
        recv_after = self.per_msg(node1, node0, "recv")
        assert recv_after.get("cmpctaggblk", 0) > recv_before.get("cmpctaggblk", 0)
        for msgtype in ["aggblocktxn", "blocktxn", "block"]:
            assert_equal(recv_after.get(msgtype, 0), recv_before.get(msgtype, 0))

    def test_fetch_missing_components(self):
        self.log.info("A peer missing some components fetches only those, not the whole aggregate")
        node0, node1, _ = self.nodes
        # Two components reach node1's mempool and are then lost by a restart;
        # a third arrives after it reconnects.
        self.send(2)
        self.sync_mempools(self.nodes[:2])
        self.restart_node(1, extra_args=["-persistmempool=0"])
        assert_equal(node1.getrawmempool(), [])
        self.connect_nodes(1, 0)
        self.send(1)
        self.wait_until(lambda: len(node1.getrawmempool()) == 1)
        assert_equal(len(node0.getrawmempool()), 3)

        recv_before = self.per_msg(node1, node0, "recv")
        sent_before = self.per_msg(node0, node1, "sent")
        with node1.assert_debug_log(expected_msgs=["Rebuilt aggregate transaction of block", "from 3 components",
                                                   "and 2 txn requested"]):
            block_hash = self.mine_aggregate_block()
        assert_equal(node1.getbestblockhash(), block_hash)
        recv_after = self.per_msg(node1, node0, "recv")
        sent_after = self.per_msg(node0, node1, "sent")
        assert recv_after.get("cmpctaggblk", 0) > recv_before.get("cmpctaggblk", 0)
        assert recv_after.get("aggblocktxn", 0) > recv_before.get("aggblocktxn", 0)
        assert sent_after.get("aggblocktxn", 0) > sent_before.get("aggblocktxn", 0)
        for msgtype in ["blocktxn", "block"]:
            assert_equal(recv_after.get(msgtype, 0), recv_before.get(msgtype, 0))

    def test_version2_peer(self):
        self.log.info("A peer that did not announce version 3 never gets a cmpctaggblk")
        node0, _, node2 = self.nodes
        assert_equal(node2.getbestblockhash(), node0.getbestblockhash())
        sent = self.per_msg(node0, node2, "sent")
        assert_equal(sent.get("cmpctaggblk", 0), 0)
        assert_equal(sent.get("aggblocktxn", 0), 0)


if __name__ == "__main__":
    CompactAggregateBlocksTest(__file__).main()
