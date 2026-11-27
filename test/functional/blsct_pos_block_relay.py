#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""A proof-of-stake block is still accepted after an altered copy of it.

The block hash does not commit to the proof of stake, so a copy of a block
with a changed proof has the same hash as the real block. Rejecting such a
copy must not stop the node from accepting the real block later.

navio-staker stakes three blocks, B1, B2 and B3, each on the last, on node 0
while the other nodes are disconnected. Then:

- node 1 gets an altered B1 over RPC. The check made before a block that
  extends the tip is stored rejects it, so nothing is stored or dropped, and
  the real B1 is accepted.
- node 2 gets an altered B1 from a P2P peer, rejects it the same way and
  disconnects the peer, and then accepts the real B1.
- node 3 gets an altered B2 (kernel range proof) and the real B3 while it
  does not have B1 yet, so both are stored. When the real B1 arrives, B2 fails
  to connect and its stored copy is dropped. After a restart, the real B2 is
  downloaded from node 0 and B3 connects on top of it.
- node 4 is the same with the set-membership proof altered and no restart.
"""

import os
import queue
import subprocess
import threading
import time

from test_framework.messages import CBlock, from_hex, msg_block
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

MIN_STAKE = 100
STAKER_TIMEOUT = 120


def tweak_scalar(scalar):
    """Flip the low bit of a big-endian scalar, which keeps it in the field."""
    s = bytearray(scalar.s)
    s[-1] ^= 0x01
    scalar.s = bytes(s)


def altered(block_hex, field):
    block = from_hex(CBlock(), block_hex)
    if field == "omega":
        tweak_scalar(block.posProof.set_mem_proof.omega)
    else:
        tweak_scalar(block.posProof.range_proof.delta_prime)
    block.rehash()
    return block


class BlsctPosBlockRelayTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 5
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def staker_path(self):
        return os.path.join(self.config["environment"]["BUILDDIR"], "bin",
                            "navio-staker" + self.config["environment"]["EXEEXT"])

    def stake_one_block(self, node, wallet_name, coinbase_dest):
        """Run navio-staker until it reports an accepted block, then stop it."""
        parent = node.getbestblockhash()
        args = [self.staker_path(), f"-datadir={node.datadir_path}", "-rpcwait",
                "-printtoconsole=1", "-nodebuglogfile", f"-wallet={wallet_name}",
                f"-coinbasedest={coinbase_dest}"]
        staker = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = queue.Queue()

        def pump():
            for line in staker.stdout:
                lines.put(line)
            lines.put(None)
        threading.Thread(target=pump, daemon=True).start()

        timeout = STAKER_TIMEOUT * self.options.timeout_factor
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"navio-staker staked no block in {timeout:g}s")
                try:
                    line = lines.get(timeout=remaining)
                except queue.Empty:
                    continue
                assert line is not None, "navio-staker exited without staking a block"
                self.log.debug(f"staker: {line.rstrip()}")
                if "(ACCEPTED)" in line:
                    break
        finally:
            staker.kill()
            staker.wait()
        self.wait_until(lambda: node.getbestblockhash() != parent)
        block_hash = node.getbestblockhash()
        block_hex = node.getblock(block_hash, 0)
        assert from_hex(CBlock(), block_hex).IsProofOfStake()
        return block_hash, block_hex

    def store_altered_b2(self, victim, b1_hex, b2_hex, b2_hash, b3_hex, field):
        """Store an altered B2 and the real B3 before B1, then submit the real B1.

        B2 is stored because its parent has no data yet, so the check before
        storing does not apply. Connecting it after B1 fails and drops it.
        """
        victim.submitheader(b1_hex[:160])
        bad = altered(b2_hex, field)
        assert_equal(bad.hash, b2_hash)
        assert_equal(victim.submitblock(bad.serialize().hex()), "inconclusive")
        assert_equal(victim.submitblock(b3_hex), "inconclusive")
        with victim.assert_debug_log([f"Discarding the stored copy of block {b2_hash}"]):
            assert_equal(victim.submitblock(b1_hex), None)
        self.assert_not_invalid(victim, b2_hash)
        assert_raises_rpc_error(-1, "Block not found on disk", victim.getblock, b2_hash)

    def assert_not_invalid(self, node, block_hash):
        for tip in node.getchaintips():
            assert not (tip["hash"] == block_hash and tip["status"] == "invalid"), tip

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", blsct=True)
        wallet = node.get_wallet_rpc("w")
        node.createwallet(wallet_name="other", blsct=True)
        other = node.get_wallet_rpc("other")

        self.log.info("Stake from two wallets: a proof of stake needs a set of at least two staked commitments")
        self.generatetoblsctaddress(node, 101, wallet.getnewaddress(label="", address_type="blsct"))
        wallet.sendtoblsctaddress(other.getnewaddress(label="", address_type="blsct"), 2 * MIN_STAKE)
        self.generatetoblsctaddress(node, 1, wallet.getnewaddress(label="", address_type="blsct"))
        other.stakelock(MIN_STAKE)
        wallet.stakelock(MIN_STAKE)
        self.generatetoblsctaddress(node, 10, wallet.getnewaddress(label="", address_type="blsct"))

        self.log.info("navio-staker stakes three blocks the other nodes have not seen")
        self.sync_all()
        for i in range(self.num_nodes - 1):
            self.disconnect_nodes(i, i + 1)
        parent = node.getbestblockhash()
        dest = wallet.getnewaddress(label="staker", address_type="blsct")
        b1_hash, b1_hex = self.stake_one_block(node, "w", dest)
        b2_hash, b2_hex = self.stake_one_block(node, "w", dest)
        b3_hash, b3_hex = self.stake_one_block(node, "w", dest)
        assert_equal(from_hex(CBlock(), b2_hex).hashPrevBlock, int(b1_hash, 16))
        assert_equal(from_hex(CBlock(), b3_hex).hashPrevBlock, int(b2_hash, 16))
        for victim in self.nodes[1:]:
            assert_equal(victim.getbestblockhash(), parent)

        self.log.info("RPC: an altered copy of a block that extends the tip is rejected, then the real block is accepted")
        victim = self.nodes[1]
        bad = altered(b1_hex, "omega")
        assert_equal(bad.hash, b1_hash)
        with victim.assert_debug_log(["AcceptBlock: bad-blsct-pos-proof"], unexpected_msgs=["Discarding the stored copy"]):
            assert_equal(victim.submitblock(bad.serialize().hex()), "bad-blsct-pos-proof")
        assert_equal(victim.getbestblockhash(), parent)
        self.assert_not_invalid(victim, b1_hash)
        assert_equal(victim.submitblock(b1_hex), None)
        assert_equal(victim.getbestblockhash(), b1_hash)
        assert_equal(victim.submitblock(b2_hex), None)
        assert_equal(victim.getbestblockhash(), b2_hash)

        self.log.info("P2P: the peer relaying an altered copy is disconnected, then the real block is accepted")
        victim = self.nodes[2]
        peer = victim.add_p2p_connection(P2PInterface())
        with victim.assert_debug_log(["AcceptBlock: bad-blsct-pos-proof"], unexpected_msgs=["Discarding the stored copy"]):
            peer.send_message(msg_block(altered(b1_hex, "delta_prime")))
            peer.wait_for_disconnect()
        assert_equal(victim.getbestblockhash(), parent)
        self.assert_not_invalid(victim, b1_hash)
        assert_equal(victim.submitblock(b1_hex), None)
        assert_equal(victim.getbestblockhash(), b1_hash)

        self.log.info("A stored copy whose kernel range proof fails is dropped on connect")
        victim = self.nodes[3]
        self.store_altered_b2(victim, b1_hex, b2_hex, b2_hash, b3_hex, "delta_prime")
        assert_equal(victim.getbestblockhash(), b1_hash)

        self.log.info("After a restart the real block is downloaded and its stored descendant connects")
        self.restart_node(3)
        assert_equal(victim.getbestblockhash(), b1_hash)
        self.assert_not_invalid(victim, b2_hash)
        self.connect_nodes(3, 0)
        self.wait_until(lambda: victim.getbestblockhash() == b3_hash)

        self.log.info("A stored copy whose set-membership proof fails is dropped on connect, and the real block is downloaded")
        victim = self.nodes[4]
        self.store_altered_b2(victim, b1_hex, b2_hex, b2_hash, b3_hex, "omega")
        self.connect_nodes(4, 0)
        self.wait_until(lambda: victim.getbestblockhash() == b3_hash)

        self.log.info("All nodes agree on the chain")
        for i in range(1, self.num_nodes - 1):
            self.connect_nodes(i, i + 1)
        self.sync_blocks()


if __name__ == "__main__":
    BlsctPosBlockRelayTest(__file__).main()
