#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test private output fetch (getpirhint/pirhint, pirquery/pirreply, -peerpir).

A light-wallet client finds an output with getoutkeys, maps it to an
(epoch, index) with the per-block counts in pirhint, and fetches its record
with a SimplePIR query. The client side (public matrix expansion, LWE query,
decoding) is done here in plain Python; the retrieved record must hash to the
output hash getoutkeys reported. The error term uses Python's random.gauss
rounded to integers, which is fine for a test but is not the constant-time
discrete Gaussian sampler a real client needs (see pir::SampleError).
"""

import random
import struct
from decimal import Decimal

from test_framework.crypto.chacha20 import chacha20_block
from test_framework.messages import (
    NODE_OUTKEYS_PIR,
    hash256,
    msg_getoutkeys,
    msg_getpirhint,
    msg_pirquery,
    ser_string,
    ser_uint256,
    uint256_from_str,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

LWE_N = 1024
DELTA = 1 << 24
MASK = 0xffffffff
EPOCH_BLOCKS = 50
RECORD_BYTES = 1152


class PirClient(P2PInterface):
    def __init__(self):
        super().__init__()
        self.outkeys = []
        self.hints = []
        self.replies = []

    def on_inv(self, message):
        # Do not fetch announced blocks: the test framework cannot parse BLSCT blocks.
        pass

    def on_outkeys(self, message):
        self.outkeys.append(message)

    def on_pirhint(self, message):
        self.hints.append(message)

    def on_pirreply(self, message):
        self.replies.append(message)


def epoch_seed(genesis_hash, epoch):
    return hash256(ser_string(b"navio/simplepir/A/v1") + ser_uint256(genesis_hash) + struct.pack("<I", epoch))


def matrix_row(seed_bytes, j):
    """Row j of the public matrix A: ChaCha20 keystream words 1024*j .. 1024*(j+1)."""
    words = []
    for block in range(64 * j, 64 * (j + 1)):
        words.extend(struct.unpack("<16I", chacha20_block(seed_bytes, b"\x00" * 12, block)))
    return words


class Query:
    """One SimplePIR query for record `index` of a database with k = 1."""

    def __init__(self, hint_msg, index):
        assert_equal(hint_msg.records_per_col, 1)
        seed = ser_uint256(hint_msg.seed)
        self.secret = [random.getrandbits(32) for _ in range(LWE_N)]
        self.query = []
        for j in range(hint_msg.num_records):
            row = matrix_row(seed, j)
            value = sum(a * s for a, s in zip(row, self.secret))
            value += round(random.gauss(0, 6.4))
            if j == index:
                value += DELTA
            self.query.append(value & MASK)

    def decode(self, hint_words, answer):
        assert_equal(len(answer), RECORD_BYTES)
        out = bytearray()
        for b in range(RECORD_BYTES):
            row = hint_words[b * LWE_N:(b + 1) * LWE_N]
            noisy = (answer[b] - sum(h * s for h, s in zip(row, self.secret))) & MASK
            out.append(((noisy + DELTA // 2) >> 24) & 0xff)
        return bytes(out)


def has_blsct_keys(vout):
    zero = "c0" + "00" * 47
    return any(vout.get(k, zero) != zero for k in ("ephemeralKey", "blindingKey", "spendingKey"))


def record_payload(record):
    assert_equal(record[0], 1)  # PIR_RECORD_OUTPUT
    length = record[1] | (record[2] << 8)
    assert all(b == 0 for b in record[3 + length:])
    return record[3:3 + length]


class P2POutKeysPirTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.pir_args = ["-peeroutkeys", "-peerpir", f"-pirepochblocks={EPOCH_BLOCKS}"]
        self.extra_args = [self.pir_args, []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", blsct=True)
        self.wallet = node.get_wallet_rpc("w")
        self.addr = self.wallet.getnewaddress(label="", address_type="blsct")
        self.generatetoblsctaddress(node, 101, self.addr)

        self.log.info("Build blocks with BLSCT sends in epoch 2")
        for i in range(2):
            dest = self.wallet.getnewaddress(label="", address_type="blsct")
            self.wallet.sendtoblsctaddress(dest, Decimal("1"), f"pir-{i}")
            self.generatetoblsctaddress(node, 1, self.addr)
        self.sync_all()

        self.log.info("Only the node with -peerpir advertises NODE_OUTKEYS_PIR")
        assert "OUTKEYS_PIR" in node.getnetworkinfo()["localservicesnames"]
        assert "OUTKEYS_PIR" not in self.nodes[1].getnetworkinfo()["localservicesnames"]
        assert int(node.getnetworkinfo()["localservices"], 16) & NODE_OUTKEYS_PIR

        self.test_fetch(node)
        self.test_bad_requests(node)
        self.test_budget(node)
        self.test_not_served(self.nodes[1])

        self.log.info("-peerpir needs -peeroutkeys")
        self.stop_node(1)
        self.nodes[1].assert_start_raises_init_error(
            extra_args=["-peerpir"],
            expected_msg="Error: Cannot set -peerpir without -peeroutkeys.")

    def get_hint(self, client, epoch):
        client.hints.clear()
        client.send_message(msg_getpirhint(epoch=epoch))
        client.wait_until(lambda: len(client.hints) >= 1)
        client.sync_with_ping()
        assert_equal(len(client.hints), 1)  # records_per_col is 1 for small epochs
        return client.hints[0]

    def query(self, client, hint, index):
        q = Query(hint, index)
        client.replies.clear()
        client.send_message(msg_pirquery(epoch=hint.epoch, anchor_hash=hint.anchor_hash,
                                         num_records=hint.num_records, query=q.query))
        client.wait_until(lambda: len(client.replies) == 1)
        reply = client.replies[0]
        assert_equal(reply.epoch, hint.epoch)
        assert_equal(reply.anchor_hash, hint.anchor_hash)
        return q, reply

    def test_fetch(self, node):
        epoch = 2
        start = epoch * EPOCH_BLOCKS
        tip = node.getblockcount()
        assert start < tip < start + EPOCH_BLOCKS
        genesis = int(node.getblockhash(0), 16)

        client = node.add_p2p_connection(PirClient())
        self.log.info("getoutkeys for the epoch so far")
        client.send_message(msg_getoutkeys(start_height=start, stop_hash=int(node.getbestblockhash(), 16)))
        client.wait_until(lambda: len(client.outkeys) == tip - start + 1)
        outkeys = list(client.outkeys)

        self.log.info("getpirhint describes the epoch consistently with outkeys")
        hint = self.get_hint(client, epoch)
        assert_equal(hint.epoch, epoch)
        assert_equal(hint.epoch_blocks, EPOCH_BLOCKS)
        assert_equal(hint.start_height, start)
        assert_equal(hint.anchor_hash, int(node.getbestblockhash(), 16))
        assert_equal(hint.block_counts, [len(m.outputs) for m in outkeys])
        assert_equal(hint.num_records, sum(hint.block_counts))
        assert_equal(hint.record_bytes, RECORD_BYTES)
        assert_equal(ser_uint256(hint.seed), epoch_seed(genesis, epoch))
        assert_equal(len(hint.hint), RECORD_BYTES * LWE_N)

        self.log.info("Fetch the outputs of a send by PIR; each record hashes to its outkeys output hash")
        # The first block of the epoch with a transaction besides the coinbase.
        for height in range(start, tip + 1):
            block = node.getblock(node.getblockhash(height), 2)
            if len(block["tx"]) > 1:
                break
        tx = block["tx"][1]
        tx_size = len(bytes.fromhex(tx["hex"]))
        tx_out_ids = {int(v["hash"], 16) for v in tx["vout"]}
        block_outkeys = outkeys[height - start]
        positions = [p for p, e in enumerate(block_outkeys.outputs) if e.out_id in tx_out_ids]
        assert len(positions) >= 2
        for pos in positions[:2]:
            index = sum(hint.block_counts[:height - start]) + pos
            q, reply = self.query(client, hint, index)
            record = q.decode(hint.hint, reply.answer)
            payload = record_payload(record)
            assert_equal(uint256_from_str(hash256(payload)), block_outkeys.outputs[pos].out_id)
        self.log.info(f"Sizes: record {RECORD_BYTES} B, output {len(payload)} B, whole send tx {tx_size} B, "
                      f"query {4 * hint.num_records} B, answer {4 * RECORD_BYTES} B, hint {4 * len(hint.hint)} B")

        self.log.info("After more blocks in the epoch an older hint still works (prefix of the database)")
        old_hint = hint
        self.generatetoblsctaddress(node, 2, self.addr)
        new_hint = self.get_hint(client, epoch)
        assert new_hint.num_records > old_hint.num_records
        assert new_hint.anchor_hash != old_hint.anchor_hash
        index = sum(old_hint.block_counts[:height - start]) + positions[0]
        q, reply = self.query(client, old_hint, index)
        payload = record_payload(q.decode(old_hint.hint, reply.answer))
        assert_equal(uint256_from_str(hash256(payload)), block_outkeys.outputs[positions[0]].out_id)
        # The last record of the new version.
        q, reply = self.query(client, new_hint, new_hint.num_records - 1)
        last_block = node.getblock(node.getbestblockhash(), 2)
        last_ids = [int(v["hash"], 16) for t in last_block["tx"] for v in t["vout"] if has_blsct_keys(v)]
        payload = record_payload(q.decode(new_hint.hint, reply.answer))
        assert_equal(uint256_from_str(hash256(payload)), last_ids[-1])

        self.log.info("A query anchored at a block that was reorganised away gets an empty reply")
        stale_tip = node.getbestblockhash()
        node.invalidateblock(stale_tip)
        self.generatetoblsctaddress(node, 2, self.addr, sync_fun=self.no_op)
        q, reply = self.query(client, new_hint, 0)
        assert_equal(reply.answer, [])
        # The rebuilt epoch serves the new chain.
        rebuilt = self.get_hint(client, epoch)
        assert_equal(rebuilt.anchor_hash, int(node.getbestblockhash(), 16))
        q, reply = self.query(client, rebuilt, 0)
        payload = record_payload(q.decode(rebuilt.hint, reply.answer))
        assert_equal(uint256_from_str(hash256(payload)), outkeys[0].outputs[0].out_id)
        node.disconnect_p2ps()
        node.reconsiderblock(stale_tip)
        self.sync_all()

    def expect_disconnect(self, node, msg):
        client = node.add_p2p_connection(PirClient())
        client.send_message(msg)
        client.wait_for_disconnect()

    def test_bad_requests(self, node):
        epoch = 2
        hint = self.get_hint(node.add_p2p_connection(PirClient()), epoch)
        node.disconnect_p2ps()
        good = [0] * hint.num_records

        self.log.info("A hint request for an epoch above the tip disconnects")
        self.expect_disconnect(node, msg_getpirhint(epoch=epoch + 1))

        self.log.info("A query of the wrong length disconnects")
        self.expect_disconnect(node, msg_pirquery(epoch, hint.anchor_hash, hint.num_records, good + [0]))
        self.expect_disconnect(node, msg_pirquery(epoch, hint.anchor_hash, hint.num_records, good[:-1]))

        self.log.info("A query whose record count does not match its anchor disconnects")
        self.expect_disconnect(node, msg_pirquery(epoch, hint.anchor_hash, hint.num_records + 1, good + [0]))

        self.log.info("A query anchored outside its epoch, or at an unknown block, disconnects")
        self.expect_disconnect(node, msg_pirquery(epoch - 1, hint.anchor_hash, hint.num_records, good))
        self.expect_disconnect(node, msg_pirquery(epoch, 1, hint.num_records, good))

        self.log.info("A well-formed query is still answered")
        client = node.add_p2p_connection(PirClient())
        client.send_message(msg_pirquery(epoch, hint.anchor_hash, hint.num_records, good))
        client.wait_until(lambda: len(client.replies) == 1)
        assert_equal(len(client.replies[0].answer), RECORD_BYTES)
        node.disconnect_p2ps()

    def test_budget(self, node):
        self.log.info("A peer over its work budget is disconnected")
        hint_bytes = RECORD_BYTES * LWE_N * 4
        # Room for one hint but not two (refill is 1/8 of the budget per second).
        self.restart_node(0, extra_args=self.pir_args + [f"-pirpeerbudget={hint_bytes + hint_bytes // 2}"])
        client = node.add_p2p_connection(PirClient())
        self.get_hint(client, 2)
        client.send_message(msg_getpirhint(epoch=2))
        client.wait_for_disconnect()
        self.restart_node(0, extra_args=self.pir_args)
        self.connect_nodes(0, 1)

    def test_not_served(self, node):
        self.log.info("A node without -peerpir disconnects PIR requests")
        self.expect_disconnect(node, msg_getpirhint(epoch=0))
        self.expect_disconnect(node, msg_pirquery(0, int(node.getblockhash(0), 16), 1, [0]))


if __name__ == '__main__':
    P2POutKeysPirTest(__file__).main()
