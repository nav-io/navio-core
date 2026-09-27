#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test getoutkeys/outkeys (NODE_OUTKEYS, -peeroutkeys).

A P2P client requests the output keys for a range of blocks and checks every
outkeys reply against the node's own view of those blocks (getblock): the
outputs carrying BLSCT keys with their hashes and keys, in block order, and the
output hashes the block spends.
"""

from decimal import Decimal

from test_framework.messages import (
    NODE_OUTKEYS,
    msg_getoutkeys,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Compressed encoding of the G1 identity, which is what an unset key holds.
ZERO_G1 = "c0" + "00" * 47


class OutKeysClient(P2PInterface):
    def __init__(self):
        super().__init__()
        self.outkeys = []

    def on_outkeys(self, message):
        self.outkeys.append(message)


def expected_outkeys(node, blockhash):
    """(outputs, spent) the node should report for a block."""
    block = node.getblock(blockhash, 2)
    outputs = []
    spent = []
    for tx in block["tx"]:
        for vout in tx["vout"]:
            keys = [vout.get(k, ZERO_G1) for k in ("ephemeralKey", "blindingKey", "spendingKey")]
            if all(k == ZERO_G1 for k in keys):
                continue
            spending_key = vout["spendingKey"]
            script = "" if spending_key != ZERO_G1 else vout["scriptPubKey"]["hex"]
            outputs.append((vout["hash"], vout["blindingKey"], spending_key, vout["viewTag"], script))
        for vin in tx["vin"]:
            if "coinbase" in vin:
                continue
            spent.append(vin["outid"])
    return outputs, spent


class P2POutKeysTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [["-peeroutkeys"], []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", blsct=True)
        wallet = node.get_wallet_rpc("w")
        addr = wallet.getnewaddress(label="", address_type="blsct")
        self.generatetoblsctaddress(node, 101, addr)

        self.log.info("Build blocks with BLSCT sends so outputs are created and spent")
        for i in range(3):
            dest = wallet.getnewaddress(label="", address_type="blsct")
            wallet.sendtoblsctaddress(dest, Decimal("1"), f"outkeys-{i}")
            self.generatetoblsctaddress(node, 1, addr)
        self.sync_all()

        self.log.info("Only the node with -peeroutkeys advertises NODE_OUTKEYS")
        assert "OUTKEYS" in node.getnetworkinfo()["localservicesnames"]
        assert "OUTKEYS" not in self.nodes[1].getnetworkinfo()["localservicesnames"]
        assert node.getnetworkinfo()["localservices"] and int(node.getnetworkinfo()["localservices"], 16) & NODE_OUTKEYS

        self.test_range(node)
        self.test_reply_budget(node)
        self.test_bad_requests(node)
        self.test_not_served(self.nodes[1])

        self.log.info("-peeroutkeys is incompatible with pruning")
        self.stop_node(1)
        self.nodes[1].assert_start_raises_init_error(
            extra_args=["-peeroutkeys", "-prune=550"],
            expected_msg="Error: Cannot set -peeroutkeys together with -prune.")

    def test_range(self, node):
        self.log.info("A range request gets one outkeys per block matching getblock")
        tip_height = node.getblockcount()
        start_height = tip_height - 9
        stop_hash = node.getblockhash(tip_height)

        client = node.add_p2p_connection(OutKeysClient())
        client.send_message(msg_getoutkeys(start_height=start_height, stop_hash=int(stop_hash, 16)))
        client.wait_until(lambda: len(client.outkeys) == 10)

        saw_spend = False
        saw_tx_outputs = False
        for i, msg in enumerate(client.outkeys):
            blockhash = node.getblockhash(start_height + i)
            assert_equal(msg.block_hash, int(blockhash, 16))
            outputs, spent = expected_outkeys(node, blockhash)
            got = [(f"{e.out_id:064x}", e.blinding_key.hex(), e.spending_key.hex(), e.view_tag, e.script.hex())
                   for e in msg.outputs]
            assert_equal(got, outputs)
            assert_equal([f"{h:064x}" for h in msg.spent], spent)
            saw_spend |= len(spent) > 0
            saw_tx_outputs |= len(outputs) > 1
        # The range covers the blocks with sends, so it must exercise both
        # non-coinbase outputs and spends.
        assert saw_spend and saw_tx_outputs

        self.log.info("A single-block request works")
        client.outkeys.clear()
        client.send_message(msg_getoutkeys(start_height=tip_height, stop_hash=int(stop_hash, 16)))
        client.wait_until(lambda: len(client.outkeys) == 1)
        assert_equal(client.outkeys[0].block_hash, int(stop_hash, 16))
        node.disconnect_p2ps()

    def request(self, node, start_height, stop_hash):
        client = node.add_p2p_connection(OutKeysClient())
        client.send_message(msg_getoutkeys(start_height=start_height, stop_hash=int(stop_hash, 16)))
        client.sync_with_ping()
        replies = list(client.outkeys)
        node.disconnect_p2ps()
        return replies

    def test_reply_budget(self, node):
        self.log.info("A reply stops at the byte budget and the client continues from the next height")
        tip_height = node.getblockcount()
        start_height = tip_height - 9
        stop_hash = node.getblockhash(tip_height)
        full = self.request(node, start_height, stop_hash)
        assert_equal(len(full), 10)
        sizes = [len(m.serialize()) for m in full]

        # A budget that fits exactly the first three blocks.
        budget = sum(sizes[:3])
        self.restart_node(0, extra_args=["-peeroutkeys", f"-outkeysmaxbytes={budget}"])
        first = self.request(node, start_height, stop_hash)
        assert_equal(len(first), 3)
        assert_equal([m.serialize() for m in first], [m.serialize() for m in full[:3]])

        # Continuing from the height after the last block received walks the
        # rest of the range, and the pieces add up to the unbudgeted reply.
        received = list(first)
        while len(received) < len(full):
            received += self.request(node, start_height + len(received), stop_hash)
        assert_equal([m.serialize() for m in received], [m.serialize() for m in full])

        self.log.info("A block larger than the budget is still sent on its own")
        self.restart_node(0, extra_args=["-peeroutkeys", "-outkeysmaxbytes=1"])
        replies = self.request(node, start_height, stop_hash)
        assert_equal([m.serialize() for m in replies], [full[0].serialize()])

        self.restart_node(0, extra_args=["-peeroutkeys"])
        node.loadwallet("w")
        self.connect_nodes(0, 1)

    def test_bad_requests(self, node):
        tip_hash = int(node.getbestblockhash(), 16)
        tip_height = node.getblockcount()

        self.log.info("Start height above the stop block disconnects")
        client = node.add_p2p_connection(OutKeysClient())
        client.send_message(msg_getoutkeys(start_height=tip_height + 1, stop_hash=tip_hash))
        client.wait_for_disconnect()

        self.log.info("Unknown stop hash disconnects")
        client = node.add_p2p_connection(OutKeysClient())
        client.send_message(msg_getoutkeys(start_height=0, stop_hash=1))
        client.wait_for_disconnect()

        self.log.info("More than 1000 blocks disconnects")
        # Extend the chain past the limit: heights 2..1001 are exactly 1000
        # blocks and are served, 1..1001 is one too many.
        wallet = node.get_wallet_rpc("w")
        addr = wallet.getnewaddress(label="", address_type="blsct")
        while node.getblockcount() < 1001:
            self.generatetoblsctaddress(node, min(100, 1001 - node.getblockcount()), addr)
        tip_hash = int(node.getbestblockhash(), 16)
        assert_equal(node.getblockcount(), 1001)
        client = node.add_p2p_connection(OutKeysClient())
        client.send_message(msg_getoutkeys(start_height=2, stop_hash=tip_hash))
        client.sync_with_ping()
        assert_equal(len(client.outkeys), 1000)
        client.send_message(msg_getoutkeys(start_height=1, stop_hash=tip_hash))
        client.wait_for_disconnect()

    def test_not_served(self, node):
        self.log.info("A node without -peeroutkeys disconnects getoutkeys")
        client = node.add_p2p_connection(OutKeysClient())
        client.send_message(msg_getoutkeys(start_height=0, stop_hash=int(node.getbestblockhash(), 16)))
        client.wait_for_disconnect()


if __name__ == '__main__':
    P2POutKeysTest(__file__).main()
