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
from test_framework.script_util import key_to_p2wpkh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

MIN_STAKE = 10000
VERSION_BIT_POS = 0x01000000  # CBlockHeader::VERSION_BIT_POS
STAKER_TIMEOUT = 120


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
        self.mine(node, 1, wallet.getnewaddress(label="", address_type="blsct"), self.key)
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
        assert node.getblock(node.getbestblockhash())["version"] & VERSION_BIT_POS
        self.sync_blocks([node, self.nodes[1]])

        self.log.info("A proof-of-stake block signed for another challenge is rejected")
        assert_equal(self.nodes[2].submitblock(node.getblock(node.getbestblockhash(), 0)), "bad-signet-blksig")

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
