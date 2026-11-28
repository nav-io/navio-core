#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Copyright (c) 2026-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the BLSCT signet: only blocks signed for the challenge are valid,
for both the proof-of-work and the proof-of-stake phase."""

import os
import queue
import subprocess
import threading
import time

from test_framework.key import ECKey
from test_framework.messages import CBlock, from_hex
from test_framework.script import CScript
from test_framework.script_util import key_to_p2wpkh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

MIN_STAKE = 10000
STAKER_TIMEOUT = 120
# Signet's nLastPOWHeight: above it every block must be proof-of-stake.
LAST_POW_HEIGHT = 1000
# Marks the push in the coinbase witness commitment that carries the solution.
SIGNET_HEADER = b"\xec\xc7\xda\xa2"


def make_key():
    key = ECKey()
    key.generate()
    return key


class SignetBasicTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.key = make_key()
        self.other_key = make_key()
        self.challenge = key_to_p2wpkh_script(self.key.get_pubkey().get_bytes()).hex()
        self.other_challenge = key_to_p2wpkh_script(self.other_key.get_pubkey().get_bytes()).hex()
        self.extra_args = [
            [f"-signetchallenge={self.challenge}"],
            [f"-signetchallenge={self.challenge}"],
            [f"-signetchallenge={self.other_challenge}"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        # Node 2 runs a different signet (another challenge, so another
        # network magic) and is kept apart.
        self.connect_nodes(0, 1)

    def key_hex(self, key):
        return key.get_bytes().hex()

    def assert_block_round_trips(self, node, block_hash):
        """The framework's CBlock parses the block and serializes it back."""
        block_hex = node.getblock(block_hash, 0)
        block = from_hex(CBlock(), block_hex)
        block.rehash()
        assert_equal(block.hash, block_hash)
        assert_equal(len(block.vtx), len(node.getblock(block_hash)["tx"]))
        assert_equal(block.serialize().hex(), block_hex)
        return block

    def strip_signet_solution(self, block):
        """Cut the solution from the coinbase, leaving the bare header push
        the signature commits to, and fix up the merkle root and hash."""
        coinbase = block.vtx[0]
        stripped = 0
        for out in coinbase.vout:
            ops = list(CScript(out.scriptPubKey))
            for i, op in enumerate(ops):
                if isinstance(op, bytes) and len(op) > len(SIGNET_HEADER) and op.startswith(SIGNET_HEADER):
                    ops[i] = SIGNET_HEADER
                    stripped += 1
            out.scriptPubKey = bytes(CScript(ops))
        assert_equal(stripped, 1)
        coinbase.rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()

    def mine(self, node, nblocks, address, key, sync_fun=None):
        # Node 2 is on another signet, so only nodes 0 and 1 can sync.
        sync_fun = sync_fun or (lambda: self.sync_blocks(self.nodes[:2]))
        return self.generatetoblsctaddress(node, nblocks, address, 1000000, self.key_hex(key), sync_fun=sync_fun)

    def run_test(self):
        node = self.nodes[0]

        self.log.info("getmininginfo")
        mining_info = node.getmininginfo()
        assert_equal(mining_info['blocks'], 0)
        assert_equal(mining_info['chain'], 'signet')

        node.createwallet(wallet_name="w", blsct=True)
        wallet = node.get_wallet_rpc("w")
        address = wallet.getnewaddress(label="", address_type="blsct")
        assert address.startswith("snv"), address

        self.log.info("Blocks must be signed with a key that satisfies the challenge")
        assert_raises_rpc_error(-8, "pass the signetkey argument", node.rpc.generatetoblsctaddress, 1, address)
        assert_raises_rpc_error(-8, "the signing keys cannot satisfy the signet challenge",
                                node.rpc.generatetoblsctaddress, 1, address, 1000000, self.key_hex(self.other_key))
        assert_raises_rpc_error(-5, "Invalid signetkey", node.rpc.generatetoblsctaddress, 1, address, 1000000, "00")
        assert_equal(node.getblockcount(), 0)

        self.log.info("Signed proof-of-work blocks are accepted and relayed")
        self.mine(node, 101, address, self.key)
        assert_equal(self.nodes[1].getblockcount(), 101)

        self.log.info("A block signed for another challenge is rejected")
        self.nodes[2].createwallet(wallet_name="w", blsct=True)
        other_address = self.nodes[2].get_wallet_rpc("w").getnewaddress(label="", address_type="blsct")
        other_hash = self.mine(self.nodes[2], 1, other_address, self.other_key, sync_fun=self.no_op)[0]
        other_block = self.nodes[2].getblock(other_hash, 0)
        assert_equal(node.submitblock(other_block), "bad-signet-blksig")

        self.test_staking(node, wallet)
        self.test_transparent_miners_above_last_pow(self.nodes[2], other_address)
        self.test_init_errors()

    def staker_path(self):
        return os.path.join(self.config["environment"]["BUILDDIR"], "bin",
                            "navio-staker" + self.config["environment"]["EXEEXT"])

    def spawn_staker(self, node, extra_args):
        args = [self.staker_path(), f"-datadir={node.datadir_path}", "-rpcwait",
                "-printtoconsole=1", "-nodebuglogfile"] + extra_args
        staker = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        staker.lines = queue.Queue()

        def pump():
            for line in staker.stdout:
                staker.lines.put(line)
            staker.lines.put(None)
        threading.Thread(target=pump, daemon=True).start()
        return staker

    def wait_for_staker_line(self, staker, needle):
        """Read staker output until a line contains needle (True) or the
        output ends (False), failing once the timeout passes."""
        timeout = STAKER_TIMEOUT * self.options.timeout_factor
        deadline = time.monotonic() + timeout
        while True:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise queue.Empty
                line = staker.lines.get(timeout=remaining)
            except queue.Empty:
                raise AssertionError(f"staker printed no line containing {needle!r} in {timeout:g}s") from None
            if line is None:
                return False
            self.log.debug(f"staker: {line.rstrip()}")
            if needle in line:
                return True

    def test_staking(self, node, wallet):
        self.log.info("navio-staker refuses to run on signet without -signetblockkey")
        coinbase_dest = wallet.getnewaddress(label="staker", address_type="blsct")
        staker = self.spawn_staker(node, ["-wallet=w", f"-coinbasedest={coinbase_dest}"])
        assert self.wait_for_staker_line(staker, "set -signetblockkey")
        staker.wait()

        self.log.info("navio-staker produces signed proof-of-stake blocks")
        # A proof of stake needs a set of at least two staked commitments.
        node.createwallet(wallet_name="other", blsct=True)
        wallet.sendtoblsctaddress(node.get_wallet_rpc("other").getnewaddress(label="", address_type="blsct"), 2 * MIN_STAKE)
        send_hash = self.mine(node, 1, wallet.getnewaddress(label="", address_type="blsct"), self.key)[0]
        assert len(self.assert_block_round_trips(node, send_hash).vtx) > 1
        node.get_wallet_rpc("other").stakelock(MIN_STAKE)
        wallet.stakelock(MIN_STAKE)
        self.mine(node, 10, wallet.getnewaddress(label="", address_type="blsct"), self.key)
        height_before = node.getblockcount()
        staker = self.spawn_staker(node, ["-wallet=w", f"-coinbasedest={coinbase_dest}",
                                          f"-signetblockkey={self.key_hex(self.key)}"])
        try:
            assert self.wait_for_staker_line(staker, "(ACCEPTED)"), "the staker did not produce an accepted block"
        finally:
            staker.kill()
            staker.wait()
        self.wait_until(lambda: node.getblockcount() > height_before)
        assert self.assert_block_round_trips(node, node.getbestblockhash()).IsProofOfStake()
        self.sync_blocks([node, self.nodes[1]])

        self.log.info("A proof-of-stake block signed for another challenge is rejected")
        assert_equal(self.nodes[2].submitblock(node.getblock(node.getbestblockhash(), 0)), "bad-signet-blksig")

        self.log.info("A proof-of-stake block with its signet solution stripped is rejected")
        block = from_hex(CBlock(), node.getblock(node.getbestblockhash(), 0))
        assert_equal(block.calc_merkle_root(), block.hashMerkleRoot)
        self.strip_signet_solution(block)
        assert block.hash != node.getbestblockhash()
        assert_equal(self.nodes[1].submitblock(block.serialize().hex()), "bad-signet-blksig")

    def test_transparent_miners_above_last_pow(self, node, address):
        """The transparent-coinbase miners are refused on signet as on any
        BLSCT network. Their error offers generatetoblsctaddress only while
        the next block can still be proof-of-work."""
        self.log.info("The transparent miners' error drops the proof-of-work hint once nLastPOWHeight is reached")
        script = f"raw({self.challenge})"
        refusal = ("a block paying a transparent coinbase is always rejected here, so generatetodescriptor is not "
                   f"available. Blocks above height {LAST_POW_HEIGHT} must be proof-of-stake")
        pow_hint = "; up to that height, generatetoblsctaddress can mine proof-of-work blocks instead."
        assert node.getblockcount() < LAST_POW_HEIGHT
        assert_raises_rpc_error(-1, refusal + pow_hint, self.generatetodescriptor, node, 1, script, sync_fun=self.no_op)

        # Node 2 is on a signet of its own, so nothing has to sync.
        while node.getblockcount() < LAST_POW_HEIGHT:
            self.mine(node, min(100, LAST_POW_HEIGHT - node.getblockcount()), address, self.other_key, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), LAST_POW_HEIGHT)
        assert_raises_rpc_error(-1, refusal + ".", self.generatetodescriptor, node, 1, script, sync_fun=self.no_op)
        # The next block must be proof-of-stake, which is why the hint is gone.
        assert_raises_rpc_error(-1, "late proof of work", self.mine, node, 1, address, self.other_key, sync_fun=self.no_op)

    def test_init_errors(self):
        self.log.info("test that signet logs the network magic on node start")
        with self.nodes[0].assert_debug_log(["Signet derived magic (message start)"]):
            self.restart_node(0)
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(extra_args=[],
                                                     expected_msg="Error: There is no default signet network yet: set -signetchallenge to the challenge of the signet to join.")
        self.nodes[0].assert_start_raises_init_error(extra_args=["-signetchallenge="],
                                                     expected_msg="Error: There is no default signet network yet: set -signetchallenge to the challenge of the signet to join.")
        self.nodes[0].assert_start_raises_init_error(extra_args=["-signetchallenge=abc"], expected_msg="Error: -signetchallenge must be hex, not 'abc'.")
        self.nodes[0].assert_start_raises_init_error(extra_args=["-signetchallenge=abc"] * 2, expected_msg="Error: -signetchallenge cannot be multiple values.")


if __name__ == '__main__':
    SignetBasicTest(__file__).main()
