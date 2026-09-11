#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""ZMQ push notifications for p2pmsg user messages (-zmqpubp2pmsg).

Two p2pmsg nodes; node1 publishes stored user messages over ZMQ. A message
sent 1:1 from node0 must arrive on the subscriber as a serialized store
entry whose fields match what listp2pmsgs reports, and a broadcast on a
subscribed topic must be published too (scope "broadcast").
"""
import struct
import time
from io import BytesIO

from test_framework.messages import deser_compact_size
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port

# Test may be skipped and not have zmq installed
try:
    import zmq
except ImportError:
    pass


def deser_entry(body):
    """Deserialize a p2pmsg::UserInbox::Entry."""
    f = BytesIO(body)
    entry = {}
    entry["id"] = struct.unpack("<Q", f.read(8))[0]
    entry["received_at"] = struct.unpack("<q", f.read(8))[0]
    entry["scope"] = struct.unpack("<B", f.read(1))[0]
    entry["topic"] = f.read(deser_compact_size(f)).decode()
    entry["sender_session"] = f.read(deser_compact_size(f)).hex()
    entry["payload"] = f.read(deser_compact_size(f)).hex()
    assert_equal(f.read(), b"")  # no trailing bytes
    return entry


class P2PMsgZMQTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_py3_zmq()
        self.skip_if_no_naviod_zmq()

    def run_test(self):
        n0, n1 = self.nodes
        address = f"tcp://127.0.0.1:{p2p_port(self.num_nodes)}"

        ctx = zmq.Context()
        try:
            socket = ctx.socket(zmq.SUB)
            socket.setsockopt(zmq.SUBSCRIBE, b"p2pmsg")
            socket.set(zmq.RCVTIMEO, 60000)

            args = ["-p2pmsg=1", "-p2pmsgpowbits=1", f"-zmqpubp2pmsg={address}"]
            self.restart_node(1, extra_args=args)
            self.restart_node(0, extra_args=["-p2pmsg=1", "-p2pmsgpowbits=1"])
            self.connect_nodes(0, 1)
            socket.connect(address)
            # Relax so the subscription is processed before publishing starts.
            time.sleep(0.2)

            self.log.info("1:1 message publishes a serialized entry on topic p2pmsg")
            inbox1 = n1.getp2pmsginfo()["inbox_pubkey"]
            payload = "zmq hello".encode().hex()
            assert n0.sendp2pmsg(inbox1, "chat", payload)

            topic, body, seq = socket.recv_multipart()
            assert_equal(topic, b"p2pmsg")
            entry = deser_entry(body)
            assert_equal(entry["topic"], "chat")
            assert_equal(entry["scope"], 0)  # inbox
            assert_equal(entry["payload"], payload)
            stored = n1.listp2pmsgs()
            assert_equal(stored[-1]["id"], entry["id"])
            assert_equal(stored[-1]["payload"], payload)
            first_seq = struct.unpack("<I", seq)[0]

            self.log.info("Subscribed-topic broadcast publishes too, with an incremented sequence")
            assert n1.subscribep2pmsgtopic("announce")
            assert n0.sendp2pmsg("broadcast", "announce", payload)
            topic, body, seq = socket.recv_multipart()
            assert_equal(topic, b"p2pmsg")
            entry = deser_entry(body)
            assert_equal(entry["topic"], "announce")
            assert_equal(entry["scope"], 1)  # broadcast
            assert_equal(struct.unpack("<I", seq)[0], first_seq + 1)

            self.log.info("p2pmsg zmq notifications OK")
        finally:
            ctx.destroy(linger=0)


if __name__ == '__main__':
    P2PMsgZMQTest(__file__).main()
