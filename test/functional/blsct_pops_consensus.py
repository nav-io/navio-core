#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Reject proof-of-stake blocks whose proof of stake was tampered with.

navio-staker stakes a real proof-of-stake block on node 0 while the other
nodes are disconnected, so they have never seen it. Nodes 1 and 2 each get a
copy with one value of its proof of stake changed, and must reject it as
bad-blsct-pos-proof: node 1 one of the set-membership proof, node 2 one of the
kernel range proof. Node 3 gets the block unchanged and accepts it.
"""

import os
import queue
import subprocess
import threading
import time

from test_framework.messages import CBlock, from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

MIN_STAKE = 100
STAKER_TIMEOUT = 120


def tweak_scalar(scalar):
    """Flip the low bit of a big-endian scalar, which keeps it in the field."""
    s = bytearray(scalar.s)
    s[-1] ^= 0x01
    scalar.s = bytes(s)


class BlsctPopsConsensusTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 4
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def staker_path(self):
        return os.path.join(self.config["environment"]["BUILDDIR"], "bin",
                            "navio-staker" + self.config["environment"]["EXEEXT"])

    def stake_one_block(self, node, wallet_name, coinbase_dest):
        """Run navio-staker until it reports an accepted block, then stop it."""
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
                    return
        finally:
            staker.kill()
            staker.wait()

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

        self.log.info("navio-staker stakes a proof-of-stake block the other nodes have not seen")
        self.sync_all()
        for i in range(self.num_nodes - 1):
            self.disconnect_nodes(i, i + 1)
        parent = node.getbestblockhash()
        self.stake_one_block(node, "w", wallet.getnewaddress(label="staker", address_type="blsct"))
        self.wait_until(lambda: node.getbestblockhash() != parent)
        block_hash = node.getbestblockhash()
        block_hex = node.getblock(block_hash, 0)
        block = from_hex(CBlock(), block_hex)
        assert block.IsProofOfStake()
        assert_equal(block.serialize().hex(), block_hex)
        for victim in self.nodes[1:]:
            assert_equal(victim.getbestblockhash(), parent)

        self.log.info("A changed set-membership proof is rejected")
        tampered = from_hex(CBlock(), block_hex)
        tweak_scalar(tampered.posProof.set_mem_proof.omega)
        assert_equal(self.nodes[1].submitblock(tampered.serialize().hex()), "bad-blsct-pos-proof")

        self.log.info("A changed kernel range proof is rejected")
        tampered = from_hex(CBlock(), block_hex)
        tweak_scalar(tampered.posProof.range_proof.delta_prime)
        assert_equal(self.nodes[2].submitblock(tampered.serialize().hex()), "bad-blsct-pos-proof")

        self.log.info("The untampered block is accepted")
        assert_equal(self.nodes[3].submitblock(block_hex), None)
        assert_equal(self.nodes[3].getbestblockhash(), block_hash)


if __name__ == "__main__":
    BlsctPopsConsensusTest(__file__).main()
