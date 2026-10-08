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

Topology: node1 -> node0 <- node2, node3 -> node0, node0 mines. node2 runs
-blocksonly and so does not announce version 3. node3 is cut off from node0
to receive blocks from test peers instead.

Checks:
- node1 reconstructs an aggregate block from its mempool with no round trip;
- node1, missing some components, fetches exactly those and not the block;
- node0 never sends a cmpctaggblk to node2, which still syncs;
- node3 does not relay components a peer supplied, even though they rebuild
  the aggregate;
- node3 clears a block request answered with the wrong reply type.
"""

from decimal import Decimal
from io import BytesIO
import random

from test_framework.messages import (
    BlockTransactionsRequest,
    CBlockHeader,
    HeaderAndShortIDs,
    calculate_shortid,
    hash256,
    msg_aggblocktxn,
    msg_blocktxn,
    msg_cmpctaggblk,
    msg_getaggblktxn,
    ser_compact_size,
    uint256_from_str,
)
from test_framework.p2p import (
    MESSAGEMAP,
    P2PInterface,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
)

UTXO_AMOUNT = Decimal("10.01")
SEND_AMOUNT = Decimal("10")
# Size of a serialized BLSCT signature, the last field of a BLSCT transaction.
SIGNATURE_SIZE = 96


class msg_rawblock:
    """A block message kept serialized: the framework cannot parse BLSCT blocks."""
    __slots__ = ("data",)
    msgtype = b"block"

    def deserialize(self, f):
        self.data = f.read()


MESSAGEMAP[b"block"] = msg_rawblock


class AggregatePeer(P2PInterface):
    def on_inv(self, message):
        # Never fetch what is announced: the framework cannot parse BLSCT
        # transactions.
        pass


def getaggblktxn(block_hash, indexes):
    msg = msg_getaggblktxn()
    msg.block_txn_request = BlockTransactionsRequest(int(block_hash, 16))
    msg.block_txn_request.from_absolute(indexes)
    return msg


def cmpctaggblk(header, coinbase, components):
    """A cmpctaggblk listing components (serialized) after the prefilled coinbase."""
    msg = msg_cmpctaggblk(header=header, nonce=random.getrandbits(64))
    keys = HeaderAndShortIDs()
    keys.header = header
    keys.nonce = msg.nonce
    k0, k1 = keys.get_siphash_keys()
    msg.shortids = [calculate_shortid(k0, k1, uint256_from_str(hash256(tx))) for tx in components]
    msg.prefilled_txn_data = ser_compact_size(1) + ser_compact_size(0) + coinbase
    return msg


class CompactAggregateBlocksTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 4
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        # noban keeps a misbehaving test peer of node3 connected, so what
        # happens to its block request can be observed.
        self.extra_args = [[], [], ["-blocksonly"], ["-whitelist=noban@127.0.0.1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(1, 0)
        self.connect_nodes(2, 0)
        self.connect_nodes(3, 0)

    def mine(self, n=1, nodes=None):
        """Mine n blocks on node0 and sync them to nodes (default: all)."""
        hashes = []
        for _ in range(n):
            hashes.extend(self.generatetoblsctaddress(self.nodes[0], 1, self.miner_addr, sync_fun=lambda: self.sync_blocks(nodes)))
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

    def mine_aggregate_block(self, nodes=None):
        """Mine one block on node0 holding node0's whole mempool as one aggregate."""
        assert len(self.nodes[0].getrawmempool()) >= 2
        block_hash = self.mine(nodes=nodes)[0]
        assert_equal(len(self.nodes[0].getblock(block_hash)["tx"]), 2)
        assert_equal(self.nodes[0].getrawmempool(), [])
        return block_hash

    def run_test(self):
        node0, node1, _ = self.nodes[:3]
        node0.createwallet(wallet_name="funder", blsct=True)
        node0.createwallet(wallet_name="sender", blsct=True)
        node1.createwallet(wallet_name="receiver", blsct=True)
        funder = node0.get_wallet_rpc("funder")
        self.sender = node0.get_wallet_rpc("sender")
        self.miner_addr = funder.getnewaddress(label="", address_type="blsct")
        self.recv_addr = node1.get_wallet_rpc("receiver").getnewaddress(label="", address_type="blsct")

        self.mine(110)
        # Independent confirmed UTXOs, one per send below, so they are siblings.
        for _ in range(11):
            funder.sendtoblsctaddress(self.sender.getnewaddress(label="", address_type="blsct"), UTXO_AMOUNT)
        self.mine()

        self.test_reconstruct_from_mempool()
        self.test_fetch_missing_components()
        self.test_version2_peer()
        self.test_forged_components_not_relayed()
        self.test_mismatched_reply_type()

    def test_reconstruct_from_mempool(self):
        self.log.info("A peer with every component in its mempool rebuilds the aggregate without a round trip")
        node0, node1, _ = self.nodes[:3]
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
        node0, node1, _ = self.nodes[:3]
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
        node0, _, node2 = self.nodes[:3]
        assert_equal(node2.getbestblockhash(), node0.getbestblockhash())
        sent = self.per_msg(node0, node2, "sent")
        assert_equal(sent.get("cmpctaggblk", 0), 0)
        assert_equal(sent.get("aggblocktxn", 0), 0)

    def mine_unrelayed_aggregate_block(self, count):
        """Mine an aggregate block of count components on node0 while node3 is
        cut off from it. Return its hash, its header, its serialized coinbase
        and its serialized components in aggregation order."""
        node0 = self.nodes[0]
        self.send(count)
        components = [bytes.fromhex(node0.getrawtransaction(txid)) for txid in node0.getrawmempool()]
        assert_equal(len(components), count)
        block_hash = self.mine_aggregate_block(nodes=self.nodes[:3])

        header = CBlockHeader()
        header.deserialize(BytesIO(bytes.fromhex(node0.getblock(block_hash, 0))))
        assert not header.IsProofOfStake()
        coinbase_txid = node0.getblock(block_hash)["tx"][0]
        coinbase = bytes.fromhex(node0.getrawtransaction(coinbase_txid, False, block_hash))

        # node0 recovered the components from its mempool: it lists them in
        # aggregation order.
        peer = node0.add_p2p_connection(AggregatePeer())
        peer.send_and_ping(getaggblktxn(block_hash, range(1, count + 1)))
        with p2p_lock:
            served = peer.last_message["aggblocktxn"].txs_data
        node0.disconnect_p2ps()
        components.sort(key=served.find)
        assert_equal(b"".join(components), served)
        return block_hash, header, coinbase, components

    def reconnect_node3(self):
        self.nodes[3].disconnect_p2ps()
        self.connect_nodes(3, 0)
        self.sync_blocks()

    def test_forged_components_not_relayed(self):
        self.log.info("Components a peer supplied are not relayed, even though they rebuild the aggregate")
        node3 = self.nodes[3]
        self.disconnect_nodes(3, 0)
        block_hash, header, coinbase, components = self.mine_unrelayed_aggregate_block(3)
        # The aggregate's signature is the sum of its components' ones, so
        # swapping two of them gives other transactions (a wtxid covers the
        # signature) that rebuild the very same aggregate.
        forged = list(components)
        forged[0] = components[0][:-SIGNATURE_SIZE] + components[1][-SIGNATURE_SIZE:]
        forged[1] = components[1][:-SIGNATURE_SIZE] + components[0][-SIGNATURE_SIZE:]
        assert forged[0] != components[0] and forged[1] != components[1]

        attacker = node3.add_p2p_connection(AggregatePeer())
        attacker.send_message(cmpctaggblk(header, coinbase, forged))
        attacker.wait_until(lambda: "getaggblktxn" in attacker.last_message)
        attacker.send_message(msg_aggblocktxn(int(block_hash, 16), forged))
        self.wait_until(lambda: node3.getbestblockhash() == block_hash)

        downstream = node3.add_p2p_connection(AggregatePeer())
        downstream.send_and_ping(getaggblktxn(block_hash, range(1, len(forged) + 1)))
        with p2p_lock:
            served = downstream.last_message.get("aggblocktxn")
            for tx in forged[:2]:
                assert served is None or tx not in served.txs_data, "relayed a component a peer supplied"
            # node3 has no component list of its own, so it sends the block.
            assert "block" in downstream.last_message
        self.reconnect_node3()

    def test_mismatched_reply_type(self):
        self.log.info("A blocktxn answering a getaggblktxn clears the block request at once")
        node0, node3 = self.nodes[0], self.nodes[3]
        self.disconnect_nodes(3, 0)
        block_hash, header, coinbase, components = self.mine_unrelayed_aggregate_block(2)

        peer = node3.add_p2p_connection(AggregatePeer())
        peer.send_message(cmpctaggblk(header, coinbase, components))
        peer.wait_until(lambda: "getaggblktxn" in peer.last_message)
        [info] = node3.getpeerinfo()
        assert_equal(info["inflight"], [node0.getblock(block_hash)["height"]])

        reply = msg_blocktxn()
        reply.block_transactions.blockhash = int(block_hash, 16)
        with node3.assert_debug_log(expected_msgs=["blocktxn for a block we are reconstructing from a cmpctaggblk"]):
            peer.send_and_ping(reply)
        # The request was cleared at once, so the block is requested whole
        # (from this peer, which noban keeps connected).
        with p2p_lock:
            assert_equal([inv.hash for inv in peer.last_message["getdata"].inv], [int(block_hash, 16)])
        self.reconnect_node3()


if __name__ == "__main__":
    CompactAggregateBlocksTest(__file__).main()
