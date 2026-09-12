#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generic USER_DATA messaging over the p2pmsg bus (the app substrate).

Three nodes: node0 sends to node2's inbox with node1 in between, so delivery
crosses the relay (node2 is not node0's direct message target peer under stem
routing). Covers: 1:1 send/receive of a topic-framed payload, broadcast
pub/sub with topic subscriptions, minted session reply keys, the reply path an
application builds by framing its own inbox key inside the payload, poll
cursors (since_id), topic filtering, clearp2pmsgs, size/validation errors,
store + subscription persistence across restart, -p2pmsgtopic seeding and
-p2pmsgnotify, and that a non-recipient node relays but does not store.
"""

import os
import platform

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1"]


class P2PMsgUserMessagingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True
        self.extra_args = [ARGS, ARGS, ARGS]

    def run_test(self):
        n0, n1, n2 = self.nodes
        # Chain topology 0-1-2: 2 is not adjacent to 0.
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)

        info0 = n0.getp2pmsginfo()
        info2 = n2.getp2pmsginfo()
        assert "inbox_pubkey" in info2 and "identity_pubkey" in info2

        self.log.info("Topic-framed payload crosses the bus to the recipient inbox only")
        payload = "hello navio".encode().hex()
        assert n0.sendp2pmsg(info2["inbox_pubkey"], "chat", payload)

        self.wait_until(lambda: len(n2.listp2pmsgs()) >= 1, timeout=30)
        msgs = n2.listp2pmsgs()
        assert_equal(len(msgs), 1)
        assert_equal(msgs[0]["payload"], payload)
        assert_equal(msgs[0]["topic"], "chat")
        assert_equal(msgs[0]["scope"], "inbox")
        assert_equal(msgs[0]["id"], 1)
        assert "sender_session" in msgs[0]

        # The relay node carried it but must not have stored it: it is not the
        # recipient, and the payload is not decryptable under its keys.
        assert_equal(n1.listp2pmsgs(), [])
        # The sender does not receive its own message either.
        assert_equal(n0.listp2pmsgs(), [])

        self.log.info("Reply path: the application frames its own inbox key in the payload")
        # This is the chat pattern: transport adds no sender info, so the
        # first message carries the sender's own (verified) inbox key.
        reply_payload = ("reply-to:%s" % info0["inbox_pubkey"]).encode().hex()
        assert n2.sendp2pmsg(info0["inbox_pubkey"], "chat", reply_payload)
        self.wait_until(lambda: len(n0.listp2pmsgs()) >= 1, timeout=30)
        assert_equal(n0.listp2pmsgs()[0]["payload"], reply_payload)
        n0.clearp2pmsgs()

        self.log.info("Session reply key: 1:1 delivery without exposing the inbox")
        minted = n0.mintp2pmsgreplykey(600)
        assert minted["reply_pubkey"] != info0["inbox_pubkey"]
        assert n2.sendp2pmsg(minted["reply_pubkey"], "chat", payload)
        self.wait_until(lambda: len(n0.listp2pmsgs()) >= 1, timeout=30)
        sess = n0.listp2pmsgs()[0]
        assert_equal(sess["scope"], "session")
        assert_equal(sess["payload"], payload)
        n0.clearp2pmsgs()

        self.log.info("Broadcast pub/sub: only subscribed topics are stored")
        assert n2.subscribep2pmsgtopic("announce")
        assert not n2.subscribep2pmsgtopic("announce")  # already subscribed
        assert_equal(n2.listp2pmsgtopics(), ["announce"])
        n2.clearp2pmsgs()
        assert n0.sendp2pmsg("broadcast", "announce", payload)
        self.wait_until(lambda: len(n2.listp2pmsgs()) >= 1, timeout=30)
        bmsg = n2.listp2pmsgs()[0]
        assert_equal(bmsg["scope"], "broadcast")
        assert_equal(bmsg["topic"], "announce")
        # node1 relayed it (node2 got it) but is not subscribed: not stored.
        assert_equal(n1.listp2pmsgs(), [])

        self.log.info("Unsubscribe stops storage of new broadcasts")
        assert n2.unsubscribep2pmsgtopic("announce")
        before_id = max([m["id"] for m in n2.listp2pmsgs()], default=0)
        assert n0.sendp2pmsg("broadcast", "announce", payload)
        # Deliver something observable afterwards to bound the wait: a 1:1
        # message sent later must arrive while the broadcast must not.
        assert n0.sendp2pmsg(n2.getp2pmsginfo()["inbox_pubkey"], "chat", payload)
        self.wait_until(lambda: any(m["scope"] == "inbox" for m in n2.listp2pmsgs(before_id)), timeout=30)
        assert_equal([m for m in n2.listp2pmsgs(before_id) if m["scope"] == "broadcast"], [])
        n2.clearp2pmsgs()

        self.log.info("since_id cursor, max_count and topic filter")
        for i in range(3):
            n0.sendp2pmsg(info2["inbox_pubkey"], "cursors", bytes([0x42, i]).hex())
        self.wait_until(lambda: len(n2.listp2pmsgs()) >= 3, timeout=30)
        all_msgs = n2.listp2pmsgs()
        ids = [m["id"] for m in all_msgs]
        assert_equal(len(ids), 3)
        assert ids == sorted(ids)
        tail = n2.listp2pmsgs(ids[0])
        assert_equal([m["id"] for m in tail], ids[1:])
        assert_equal(len(n2.listp2pmsgs(0, 2)), 2)
        assert_equal(len(n2.listp2pmsgs(0, 0, "cursors")), 3)
        assert_equal(n2.listp2pmsgs(0, 0, "no-such-topic"), [])

        self.log.info("clearp2pmsgs drops up to the cursor, then everything")
        assert_equal(n2.clearp2pmsgs(ids[1]), 2)
        assert_equal([m["id"] for m in n2.listp2pmsgs()], ids[2:])
        assert_equal(n2.clearp2pmsgs(), 1)
        assert_equal(n2.listp2pmsgs(), [])

        self.log.info("Validation: bad recipient, bad topic, empty and oversized payloads rejected")
        assert_raises_rpc_error(-5, "invalid recipient",
                                n0.sendp2pmsg, "deadbeef", "chat", payload)
        assert_raises_rpc_error(-8, "topic must be",
                                n0.sendp2pmsg, info2["inbox_pubkey"], "", payload)
        assert_raises_rpc_error(-8, "topic must be",
                                n0.sendp2pmsg, info2["inbox_pubkey"], "t" * 65, payload)
        assert_raises_rpc_error(-8, "payload must not be empty",
                                n0.sendp2pmsg, info2["inbox_pubkey"], "chat", "")
        assert_raises_rpc_error(-8, "serialize to",
                                n0.sendp2pmsg, info2["inbox_pubkey"], "chat", "00" * 3584)

        self.log.info("Near-maximum payload still delivers")
        big = "ab" * 3560
        assert n0.sendp2pmsg(info2["inbox_pubkey"], "chat", big)
        self.wait_until(lambda: len(n2.listp2pmsgs()) >= 1, timeout=30)
        assert_equal(n2.listp2pmsgs()[0]["payload"], big)
        last_id_before_restart = n2.listp2pmsgs()[0]["id"]

        self.log.info("Store and subscriptions persist across restart; -p2pmsgtopic seeds")
        assert n2.subscribep2pmsgtopic("keepme")
        self.restart_node(2, extra_args=ARGS + ["-p2pmsgtopic=boot"])
        persisted = n2.listp2pmsgs()
        assert_equal(len(persisted), 1)
        assert_equal(persisted[0]["id"], last_id_before_restart)
        assert_equal(persisted[0]["payload"], big)
        assert_equal(sorted(n2.listp2pmsgtopics()), ["boot", "keepme"])
        n2.clearp2pmsgs()
        self.connect_nodes(1, 2)

        self.log.info("Inbox prekey rotation: messages to the new prekey deliver")
        n2.rotatep2pmsginbox()
        new_inbox = n2.getp2pmsginfo()["inbox_pubkey"]
        assert new_inbox != info2["inbox_pubkey"]
        assert n0.sendp2pmsg(new_inbox, "chat", payload)
        self.wait_until(lambda: len(n2.listp2pmsgs()) >= 1, timeout=30)
        assert_equal(n2.listp2pmsgs()[0]["payload"], payload)

        if platform.system() != "Windows":
            self.log.info("-p2pmsgnotify runs on message arrival")
            notify_file = os.path.join(self.nodes[0].datadir_path, "msg_notify.txt")
            self.restart_node(0, extra_args=ARGS + ["-p2pmsgnotify=echo %%s >> %s" % notify_file])
            self.connect_nodes(0, 1)
            info0 = n0.getp2pmsginfo()
            assert n2.sendp2pmsg(info0["inbox_pubkey"], "chat", payload)
            self.wait_until(lambda: os.path.exists(notify_file) and os.path.getsize(notify_file) > 0, timeout=30)
            with open(notify_file, encoding='utf8') as f:
                notified_id = int(f.read().split()[0])
            assert_equal(notified_id, n0.listp2pmsgs()[-1]["id"])

        self.log.info("p2pmsg user messaging OK")


if __name__ == '__main__':
    P2PMsgUserMessagingTest(__file__).main()
