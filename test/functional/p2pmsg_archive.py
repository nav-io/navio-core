#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Offline retrieval of p2pmsg envelopes from an archiving node.

The bus carries no recipient field, so a node cannot hold messages for an
offline peer: there is nothing to index on. An archiving node instead keeps the
FLAGGED envelopes it relayed and hands back the subset matching a fuzzy
detection key the requester supplies -- the requester's messages plus a
2^-precision fraction of everyone else's, with no way to tell them apart.

The scenario here is the real one: a recipient that is NOT connected to the
network at all misses a message entirely, and then retrieves it afterwards from
a node that merely relayed it and cannot read it.

Covered: the service bit, storage of flagged envelopes only, retrieval by
detection key, decoys at low precision, cursor and completeness semantics, the
query proof of work, and the caps that keep a scan from being a denial of
service.
"""

import struct
import time

from test_framework.messages import (
    NODE_P2PMSG,
    NODE_P2PMSG_ARCHIVE,
    msg_getp2pmsgs,
    sha256,
    ser_compact_size,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

# Mirrors ARCHIVE_QUERY_BURST in p2pmsg/archive.h.
ARCHIVE_QUERY_BURST = 3

POW_BITS = 2
ARCHIVE_ARGS = ["-p2pmsg=1", f"-p2pmsgpowbits={POW_BITS}", "-p2pmsgarchive=1"]
PLAIN_ARGS = ["-p2pmsg=1", f"-p2pmsgpowbits={POW_BITS}"]

FMD_SCALAR_SIZE = 32
POW_HEADER_SIZE = 1 + 8 + 1 + 48 + 32 + 8


def ser_bytes(b):
    return ser_compact_size(len(b)) + b


def query_hash(cursor, limit, precision, scan_budget, challenge, detection_key,
               not_before):
    """SHA256 over the query fields, exactly as ArchiveRequest::QueryHash()."""
    body = struct.pack("<B", 1)
    body += struct.pack("<Q", cursor)
    body += struct.pack("<H", limit)
    body += struct.pack("<B", precision)
    body += struct.pack("<I", scan_budget)
    body += challenge
    body += ser_bytes(detection_key)
    body += struct.pack("<q", not_before)
    return sha256(body)


def stamp_bits(base, scan_budget, precision):
    """Mirror of ArchiveStampBits(): base plus a term that grows with the work
    requested, capped at base+8.

    Priced on the SCAN BUDGET, not on limit: limit bounds matches, and a query
    that matches nothing still walks the whole window."""
    units = max(scan_budget, 1) * max(precision, 1)
    free_allowance = 1000 * 4
    extra = 0
    while units > free_allowance and extra < 8:
        units >>= 1
        extra += 1
    return base + extra


def grind_stamp(qhash, timestamp, bits):
    """Find a nonce whose stamp hash meets `bits`.

    UintToArith256 reads the digest LITTLE-endian, so the leading zero bits land
    in the LAST bytes -- the same convention the envelope PoW uses.
    """
    target = ((1 << 256) - 1) >> bits
    prefix = struct.pack("<B", 1) + struct.pack("<q", timestamp) + qhash
    for nonce in range(1 << 24):
        h = sha256(prefix + struct.pack("<Q", nonce))
        if int.from_bytes(h, "little") <= target:
            return prefix + struct.pack("<Q", nonce)
    raise AssertionError("could not grind an archive query stamp")


def build_request(detection_key, precision, challenge, cursor=0, limit=100,
                  not_before=0, scan_budget=1000, base_bits=POW_BITS,
                  break_pow=False, stamp=None):
    qh = query_hash(cursor, limit, precision, scan_budget, challenge,
                    detection_key, not_before)
    bits = stamp_bits(base_bits, scan_budget, precision)
    if stamp is not None:
        pass  # caller is replaying one it already has
    elif break_pow:
        # A stamp that commits correctly but was never ground.
        stamp = struct.pack("<B", 1) + struct.pack("<q", int(time.time())) + qh + struct.pack("<Q", 0)
    else:
        stamp = grind_stamp(qh, int(time.time()), bits)
    body = struct.pack("<B", 1)
    body += stamp
    body += struct.pack("<Q", cursor)
    body += struct.pack("<H", limit)
    body += struct.pack("<B", precision)
    body += struct.pack("<I", scan_budget)
    body += challenge
    body += ser_bytes(detection_key)
    body += struct.pack("<q", not_before)
    return body


def parse_response(payload):
    pos = 0
    version = payload[pos]
    pos += 1
    next_cursor = struct.unpack_from("<Q", payload, pos)[0]
    pos += 8
    complete = payload[pos]
    pos += 1
    count, pos = read_compact_size(payload, pos)
    items = []
    for _ in range(count):
        item_id = struct.unpack_from("<Q", payload, pos)[0]
        pos += 8
        received_at = struct.unpack_from("<q", payload, pos)[0]
        pos += 8
        elen, pos = read_compact_size(payload, pos)
        items.append({"id": item_id, "received_at": received_at,
                      "envelope": payload[pos:pos + elen]})
        pos += elen
    return {"version": version, "next_cursor": next_cursor,
            "complete": complete, "items": items}


def read_compact_size(buf, pos):
    n = buf[pos]
    pos += 1
    if n < 253:
        return n, pos
    if n == 253:
        return struct.unpack_from("<H", buf, pos)[0], pos + 2
    if n == 254:
        return struct.unpack_from("<I", buf, pos)[0], pos + 4
    return struct.unpack_from("<Q", buf, pos)[0], pos + 8


class ArchiveClient(P2PInterface):
    def __init__(self):
        super().__init__()
        self.responses = []
        # The challenge the node issues unsolicited right after verack. A
        # query's stamp has to commit to it.
        self.challenge = None

    def on_p2pmsgchal(self, message):
        self.challenge = message.payload[:32]

    def on_p2pmsgs(self, message):
        self.responses.append(parse_response(message.payload))

    def send_query(self, **kwargs):
        """Send one query and return the exact bytes sent.

        Returning the BODY, not the kwargs: rebuilding from kwargs grinds a
        fresh nonce, which is a new stamp and not a replay at all.
        """
        kwargs.setdefault("challenge", self.challenge)
        body = build_request(**kwargs)
        self.send_message(msg_getp2pmsgs(body))
        return body


class P2PMsgArchiveTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        # n0 sends, n1 archives and relays, n2 is the RECIPIENT and is never
        # connected to either -- it must miss the message entirely.
        self.extra_args = [PLAIN_ARGS, ARCHIVE_ARGS, PLAIN_ARGS]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def settled_responses(self, peer, at_least=1, timeout=30):
        """Number of responses once the server has stopped producing them.

        A scan runs on the node's ArchiveScanner thread, not on the message
        handler, so a returned ping says only that the QUERY was processed --
        the response may still be in flight behind it. Anything that counts
        responses has to wait for the scanner to go quiet rather than treat a
        ping as a barrier.

        Quiet is only meaningful once the scanner has started answering: on a
        slow runner the first scan can take longer than one settle interval,
        and two empty reads in a row would then pass for "settled at 0". So
        wait for `at_least` responses first, then for the count to stop moving.
        """
        peer.wait_until(lambda: len(peer.responses) >= at_least, timeout=timeout)
        deadline = time.time() + timeout
        last = -1
        while time.time() < deadline:
            peer.sync_with_ping()
            count = len(peer.responses)
            if count == last:
                return count
            last = count
            time.sleep(0.2)
        return len(peer.responses)

    def query(self, node, **kwargs):
        """One query on a FRESH connection.

        Archive queries are metered per peer (ARCHIVE_QUERY_BURST tokens,
        refilled at ARCHIVE_QUERIES_PER_MINUTE), which a test firing them
        back-to-back would otherwise trip. Reconnecting keeps each check
        independent of the others; the limiter itself is asserted separately
        below.
        """
        peer = node.add_p2p_connection(ArchiveClient(), services=NODE_P2PMSG)
        try:
            # The node issues its challenge unsolicited right after verack; a
            # stamp that does not commit to it buys nothing.
            peer.wait_until(lambda: peer.challenge is not None, timeout=30)
            peer.send_query(**kwargs)
            peer.wait_until(lambda: len(peer.responses) >= 1, timeout=30)
            return peer.responses[-1]
        finally:
            node.disconnect_p2ps()

    def run_test(self):
        n0, n1, n2 = self.nodes

        self.log.info("The archiving node advertises NODE_P2PMSG_ARCHIVE")
        # The service bit itself, not just the RPC view of it: it is what lets
        # a client find an archiving node through ADDR gossip, so a node that
        # archives without advertising is unreachable for retrieval.
        assert int(n1.getnetworkinfo()["localservices"], 16) & NODE_P2PMSG_ARCHIVE, \
            "the archiving node does not advertise NODE_P2PMSG_ARCHIVE"
        assert not int(n0.getnetworkinfo()["localservices"], 16) & NODE_P2PMSG_ARCHIVE, \
            "a non-archiving node must not advertise NODE_P2PMSG_ARCHIVE"

        info1 = n1.getp2pmsginfo()
        assert "archive" in info1
        assert_equal(info1["archive"]["entries"], 0)
        assert_equal(info1["archive"]["retention_days"], 14)
        # n0 does not archive, and says so by omission.
        assert "archive" not in n0.getp2pmsginfo()
        assert_equal(n0.getp2pmsginfo()["archive_peers"], 1)
        assert_equal(n1.getp2pmsginfo()["archive_peers"], 0)

        self.log.info("Unflagged traffic is not archived")
        recipient = n2.getp2pmsginfo()
        assert_equal(n0.sendp2pmsg(recipient["inbox_pubkey"], "plain", "01", False), True)
        self.wait_for_relay(n1)
        assert_equal(n1.getp2pmsginfo()["archive"]["entries"], 0)

        self.log.info("A flagged message is archived by the relay that cannot read it")
        assert_equal(
            n0.sendp2pmsg(recipient["inbox_pubkey"], "chat", "48656c6c6f", False,
                          recipient["fmd_clue_key"]),
            True,
        )
        self.wait_until(lambda: n1.getp2pmsginfo()["archive"]["entries"] >= 1, timeout=30)
        arch = n1.getp2pmsginfo()["archive"]
        assert_equal(arch["entries"], 1)
        assert_equal(arch["oldest_id"], 1)
        assert_equal(arch["newest_id"], 1)
        assert_greater_than(arch["bytes"], 0)

        # The recipient never saw it: it is not connected to anything.
        assert_equal(n2.listp2pmsgs(), [])

        self.log.info("The recipient retrieves it afterwards with its detection key")
        dk = n2.getp2pmsgdetectionkey(24)["detection_key"]
        resp = self.query(n1, detection_key=bytes.fromhex(dk), precision=24)
        assert_equal(resp["complete"], 1)
        assert_equal(resp["next_cursor"], 1)
        assert_equal(len(resp["items"]), 1)
        # The returned bytes are the complete envelope as relayed, so the
        # recipient runs it through exactly the same inbound path as a live one.
        envelope = resp["items"][0]["envelope"]
        assert_greater_than(len(envelope), POW_HEADER_SIZE)
        assert_equal(envelope[1 + POW_HEADER_SIZE - 98], 2)  # PoW header version 2

        self.log.info("A stranger's key at full precision matches nothing")
        stranger = n0.getp2pmsgdetectionkey(24)["detection_key"]
        resp = self.query(n1, detection_key=bytes.fromhex(stranger), precision=24)
        assert_equal(len(resp["items"]), 0)
        assert_equal(resp["complete"], 1)
        # It still scanned, so the cursor advances and the requester does not
        # re-walk the same ground next time.
        assert_equal(resp["next_cursor"], 1)

        self.log.info("Resuming from the returned cursor finds nothing new")
        resp = self.query(n1, detection_key=bytes.fromhex(dk), precision=24, cursor=1)
        assert_equal(len(resp["items"]), 0)
        assert_equal(resp["complete"], 1)

        self.log.info("Low precision returns decoys alongside the real message")
        for i in range(40):
            assert_equal(
                n0.sendp2pmsg(n0.getp2pmsginfo()["inbox_pubkey"], "decoy", f"{i:02x}", False,
                              n0.getp2pmsginfo()["fmd_clue_key"]),
                True,
            )
        self.wait_until(lambda: n1.getp2pmsginfo()["archive"]["entries"] >= 41, timeout=60)
        # At 2^-1 roughly half of the 40 messages that are NOT ours come back
        # too, and ours is always among them. That indistinguishability is the
        # entire privacy property.
        resp = self.query(n1, detection_key=bytes.fromhex(n2.getp2pmsgdetectionkey(1)["detection_key"]),
                          precision=1, limit=500)
        assert_greater_than(len(resp["items"]), 5)
        assert 1 in [item["id"] for item in resp["items"]]

        self.log.info("The response is capped and says when it stopped early")
        resp = self.query(n1, detection_key=bytes.fromhex(n2.getp2pmsgdetectionkey(1)["detection_key"]),
                          precision=1, limit=2)
        assert_equal(len(resp["items"]), 2)
        assert_equal(resp["complete"], 0)
        # "I stopped early" must never be confusable with "you have everything",
        # or a requester silently loses messages.
        assert_greater_than(resp["next_cursor"], 0)

        self.log.info("An unground query stamp is rejected")
        peer = n1.add_p2p_connection(ArchiveClient(), services=NODE_P2PMSG)
        peer.wait_until(lambda: peer.challenge is not None, timeout=30)
        peer.send_query(detection_key=bytes.fromhex(dk), precision=24, limit=500, break_pow=True)
        peer.sync_with_ping()
        assert_equal(len(peer.responses), 0)
        n1.disconnect_p2ps()

        self.log.info("A stamp is bound to the connection it was issued for")
        # Without this, one grind is spendable for its whole validity window on
        # every connection and at every archive node, and the per-peer bucket
        # does not help because a new connection brings a new bucket.
        peer = n1.add_p2p_connection(ArchiveClient(), services=NODE_P2PMSG)
        peer.wait_until(lambda: peer.challenge is not None, timeout=30)
        first_challenge = peer.challenge
        replayed = peer.send_query(detection_key=bytes.fromhex(dk), precision=24)
        peer.wait_until(lambda: len(peer.responses) >= 1, timeout=30)
        n1.disconnect_p2ps()

        # The very same bytes on a new connection: the challenge has changed,
        # so the stamp commits to the wrong query and buys nothing.
        peer = n1.add_p2p_connection(ArchiveClient(), services=NODE_P2PMSG)
        peer.wait_until(lambda: peer.challenge is not None, timeout=30)
        assert peer.challenge != first_challenge, "challenge must be per-connection"
        peer.send_message(msg_getp2pmsgs(replayed))
        peer.sync_with_ping()
        assert_equal(len(peer.responses), 0)
        assert peer.is_connected
        n1.disconnect_p2ps()

        self.log.info("A stamp cannot be spent twice on the connection it IS valid on")
        peer = n1.add_p2p_connection(ArchiveClient(), services=NODE_P2PMSG)
        peer.wait_until(lambda: peer.challenge is not None, timeout=30)
        sent = peer.send_query(detection_key=bytes.fromhex(dk), precision=24)
        peer.wait_until(lambda: len(peer.responses) >= 1, timeout=30)
        # The very same bytes, so the very same stamp -- not a re-grind, which
        # would be an ordinary second query and legitimately served.
        peer.send_message(msg_getp2pmsgs(sent))
        assert_equal(self.settled_responses(peer), 1)
        assert peer.is_connected
        n1.disconnect_p2ps()

        self.log.info("A big scan costs more proof of work than a small one")
        # The hole this closes: limit bounds MATCHES, so a high-precision key
        # that matches nothing used to return cheaply while walking the entire
        # window. The budget is now what is priced, and a stamp ground for a
        # small budget does not pay for a large one.
        peer = n1.add_p2p_connection(ArchiveClient(), services=NODE_P2PMSG)
        peer.wait_until(lambda: peer.challenge is not None, timeout=30)
        assert_greater_than(stamp_bits(POW_BITS, 50000, 24), stamp_bits(POW_BITS, 1, 24))
        cheap = build_request(detection_key=bytes.fromhex(dk), precision=24,
                              challenge=peer.challenge, scan_budget=1)
        # Re-label that stamp as buying the largest scan there is.
        expensive = build_request(detection_key=bytes.fromhex(dk), precision=24,
                                  challenge=peer.challenge, scan_budget=50000,
                                  stamp=cheap[1:1 + 1 + 8 + 32 + 8])
        peer.send_message(msg_getp2pmsgs(expensive))
        peer.sync_with_ping()
        assert_equal(len(peer.responses), 0)
        n1.disconnect_p2ps()

        self.log.info("Queries are metered per peer")
        # A scan costs the serving node real CPU. The stamp prices the SIZE of
        # one query; this bounds how OFTEN they can be asked for. A burst is
        # allowed, then the peer is throttled -- dropped silently rather than
        # banned, because a client syncing a long window legitimately issues
        # back-to-back queries and should back off, not be disconnected.
        peer = n1.add_p2p_connection(ArchiveClient(), services=NODE_P2PMSG)
        peer.wait_until(lambda: peer.challenge is not None, timeout=30)
        attempts = ARCHIVE_QUERY_BURST + 2
        for i in range(attempts):
            # Distinct cursors, so each query carries its own stamp and the
            # spent-stamp check does not stand in for the rate limiter.
            peer.send_query(detection_key=bytes.fromhex(dk), precision=24, cursor=i)
        served = self.settled_responses(peer)
        assert_greater_than(attempts, served)
        assert_greater_than(served, 0)
        assert peer.is_connected
        n1.disconnect_p2ps()

        self.log.info("A node without -p2pmsgarchive ignores the query")
        plain = n0.add_p2p_connection(ArchiveClient(), services=NODE_P2PMSG)
        # It issues no challenge either, since it has no archive to protect.
        plain.sync_with_ping()
        assert plain.challenge is None
        plain.send_message(msg_getp2pmsgs(build_request(
            detection_key=bytes.fromhex(dk), precision=24, challenge=bytes(32))))
        plain.sync_with_ping()
        assert_equal(len(plain.responses), 0)

    def wait_for_relay(self, node):
        """Give the relay a moment to process and (not) archive."""
        self.wait_until(lambda: node.getpeerinfo()[0]["bytesrecv"] > 0, timeout=30)
        node.syncwithvalidationinterfacequeue()
        time.sleep(1)


if __name__ == '__main__':
    P2PMsgArchiveTest(__file__).main()
