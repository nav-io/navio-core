#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fuzzy message detection flags on the p2pmsg envelope (envelope v2).

A flag lets a recipient who was OFFLINE retrieve a message later from an
archiving node, without the envelope ever carrying a recipient identifier.
This test covers the node-side surface of that mechanism:

  * getp2pmsginfo publishes a clue key, signed under the node's identity, and
    it rotates with the inbox prekey;
  * getp2pmsgdetectionkey derives a detection key at a chosen false-positive
    rate, and a lower precision is a prefix of a higher one;
  * sendp2pmsg accepts the recipient's clue key and delivery still works
    across a relay;
  * the flag is actually on the wire, at the documented size and position,
    and an unflagged send carries a zero-length flag field.

PoW difficulty is 1 bit so the test does not burn CPU.
"""

from test_framework.messages import NODE_P2PMSG
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error

ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1"]

# Envelope v2: u8 kind || PoWHeader || CompactSize flen || u8[flen] flag || EciesPacket
POW_HEADER_SIZE = 1 + 8 + 1 + 48 + 32 + 8  # version, timestamp, kind, eph, payload_hash, nonce
FMD_GAMMA = 24
FMD_FLAG_SIZE = 48 + 32 + FMD_GAMMA // 8   # u || y || c  = 83
FMD_CLUE_KEY_SIZE = FMD_GAMMA * 48         # 1152


def read_compact_size(buf, pos):
    """Return (value, new_pos) for a Bitcoin CompactSize at buf[pos]."""
    n = buf[pos]
    pos += 1
    if n < 253:
        return n, pos
    if n == 253:
        return int.from_bytes(buf[pos:pos + 2], "little"), pos + 2
    if n == 254:
        return int.from_bytes(buf[pos:pos + 4], "little"), pos + 4
    return int.from_bytes(buf[pos:pos + 8], "little"), pos + 8


def envelope_flag(payload):
    """Extract the detection flag from a raw p2pmsg envelope."""
    pos = 1 + POW_HEADER_SIZE
    flen, pos = read_compact_size(payload, pos)
    return payload[pos:pos + flen]


class P2PMsgCollector(P2PInterface):
    """Keeps the raw payload of every p2pmsg/dp2pmsg envelope seen."""

    def __init__(self):
        super().__init__()
        self.envelopes = []

    def on_p2pmsg(self, message):
        self.envelopes.append(message.payload)

    def on_dp2pmsg(self, message):
        self.envelopes.append(message.payload)


class P2PMsgFmdTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        # Plain regtest: nothing here touches BLSCT chain state, and the P2P
        # test framework has no magic bytes for the blsct chain.
        self.setup_clean_chain = True
        self.extra_args = [ARGS, ARGS, ARGS]

    def run_test(self):
        n0, n1, n2 = self.nodes
        # Chain 0-1-2, so delivery to n2 has to cross a relay that cannot read
        # the message and must forward the flag untouched.
        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)

        self.check_published_clue_key(n2)
        self.check_detection_key(n2)
        self.check_flagged_delivery(n0, n2)
        self.check_flag_on_the_wire(n0, n2)
        self.check_rejects_bad_clue_keys(n0, n2)
        self.check_rotation(n2)

    def check_published_clue_key(self, node):
        self.log.info("getp2pmsginfo publishes a signed clue key")
        info = node.getp2pmsginfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["fmd_gamma"], FMD_GAMMA)
        assert_equal(len(info["fmd_clue_key"]), FMD_CLUE_KEY_SIZE * 2)
        # 96-byte BLS signature over the clue key, so a sender can authenticate
        # a fetched clue key before flagging to it. Flagging to a substituted
        # key would hand the retrieval side to whoever substituted it.
        assert_equal(len(info["fmd_sig"]), 96 * 2)
        bytes.fromhex(info["fmd_clue_key"])
        bytes.fromhex(info["fmd_sig"])

    def check_detection_key(self, node):
        self.log.info("getp2pmsgdetectionkey derives keys at a chosen precision")
        low = node.getp2pmsgdetectionkey(4)
        high = node.getp2pmsgdetectionkey(8)
        assert_equal(low["precision"], 4)
        assert_equal(len(low["detection_key"]), 4 * 32 * 2)
        assert_equal(len(high["detection_key"]), 8 * 32 * 2)
        # The sub-keys are independent, and a precision-n key is the first n of
        # them: a prefix. Crucially it does NOT let the holder derive n+1, which
        # is what keeps precision the client's choice and not the detector's.
        assert high["detection_key"].startswith(low["detection_key"])
        assert_equal(float(low["false_positive_rate"]), 1 / 16)

        assert_raises_rpc_error(-8, "precision must be 1-24", node.getp2pmsgdetectionkey, 0)
        assert_raises_rpc_error(-8, "precision must be 1-24", node.getp2pmsgdetectionkey, 25)

    def check_flagged_delivery(self, sender, recipient):
        self.log.info("A flagged message is delivered normally across a relay")
        info = recipient.getp2pmsginfo()
        before = len(recipient.listp2pmsgs())
        assert_equal(
            sender.sendp2pmsg(info["inbox_pubkey"], "fmd-test", "aabb", True, info["fmd_clue_key"]),
            True,
        )
        # The flag is a retrieval hint, not part of delivery: live delivery must
        # be completely unaffected by its presence.
        self.wait_until(lambda: len(recipient.listp2pmsgs()) > before, timeout=30)
        msgs = recipient.listp2pmsgs()
        assert_equal(msgs[-1]["topic"], "fmd-test")
        assert_equal(msgs[-1]["payload"], "aabb")

    def wait_for_new_envelope(self, peer, seen):
        """Return the next envelope whose raw payload has not been seen yet.

        One send can be observed more than once (the node relays over both
        p2pmsg and dp2pmsg), and on a slow machine a late copy of the PREVIOUS
        send lands after the list was cleared. Waiting on the list length and
        reading the last entry then picks up the wrong envelope. Envelope
        payloads are unique per message, so match on the payload instead.
        """
        peer.wait_until(lambda: any(bytes(e) not in seen for e in peer.envelopes), timeout=30)
        fresh = [bytes(e) for e in peer.envelopes if bytes(e) not in seen]
        seen.update(fresh)
        return fresh[0]

    def check_flag_on_the_wire(self, sender, recipient):
        self.log.info("The flag rides the envelope at the documented size")
        info = recipient.getp2pmsginfo()
        peer = sender.add_p2p_connection(P2PMsgCollector(), services=NODE_P2PMSG)
        peer.sync_with_ping()
        seen = set()

        # Fluff so the envelope reaches every relay peer, including ours.
        assert_equal(
            sender.sendp2pmsg(info["inbox_pubkey"], "flagged", "01", False, info["fmd_clue_key"]),
            True,
        )
        flagged = envelope_flag(self.wait_for_new_envelope(peer, seen))
        assert_equal(len(flagged), FMD_FLAG_SIZE)

        # An unflagged send carries a zero-length flag field. Flagging is
        # optional and costs nothing when unused.
        assert_equal(sender.sendp2pmsg(info["inbox_pubkey"], "plain", "02", False), True)
        assert_equal(len(envelope_flag(self.wait_for_new_envelope(peer, seen))), 0)

        # Two flags to the same clue key are unlinkable: the ephemeral element
        # is fresh per message, so no two flags share bytes.
        assert_equal(
            sender.sendp2pmsg(info["inbox_pubkey"], "flagged", "03", False, info["fmd_clue_key"]),
            True,
        )
        second = envelope_flag(self.wait_for_new_envelope(peer, seen))
        assert_equal(len(second), FMD_FLAG_SIZE)
        assert second != flagged
        assert_greater_than(len(set(second) ^ set(flagged)), 0)

        sender.disconnect_p2ps()

    def check_rejects_bad_clue_keys(self, sender, recipient):
        self.log.info("Malformed clue keys are refused")
        inbox = recipient.getp2pmsginfo()["inbox_pubkey"]
        assert_raises_rpc_error(-8, "cluekey is not valid hex",
                                sender.sendp2pmsg, inbox, "t", "01", True, "zz")
        assert_raises_rpc_error(-5, "cluekey must be 1152 bytes",
                                sender.sendp2pmsg, inbox, "t", "01", True, "00" * 64)
        # Right length, but not valid curve points.
        assert_raises_rpc_error(-5, "cluekey must be 1152 bytes",
                                sender.sendp2pmsg, inbox, "t", "01", True, "ff" * FMD_CLUE_KEY_SIZE)
        # Right length, points at infinity: h_i^r would be infinity for every
        # sender, so every flag would carry the same bits and detect nothing.
        infinity = ("c0" + "00" * 47) * FMD_GAMMA
        assert_raises_rpc_error(-5, "cluekey must be 1152 bytes",
                                sender.sendp2pmsg, inbox, "t", "01", True, infinity)

    def check_rotation(self, node):
        self.log.info("Rotating the inbox prekey rotates the clue key with it")
        before = node.getp2pmsginfo()
        before_dk = node.getp2pmsgdetectionkey(8)["detection_key"]

        rotated = node.rotatep2pmsginbox()
        assert_equal(rotated["fmd_gamma"], FMD_GAMMA)
        assert rotated["fmd_clue_key"] != before["fmd_clue_key"]
        assert rotated["inbox_pubkey"] != before["inbox_pubkey"]
        assert_equal(node.getp2pmsginfo()["fmd_clue_key"], rotated["fmd_clue_key"])

        # The detection key changes with it. That is what bounds a detection
        # key's lifetime: handed to an archiving node it would otherwise keep
        # matching FUTURE flags for as long as the node runs.
        assert node.getp2pmsgdetectionkey(8)["detection_key"] != before_dk


if __name__ == '__main__':
    P2PMsgFmdTest(__file__).main()
