#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the fixed-base range-proof verification path end to end.

The -blsctfixedbase window tables cannot be exercised in-process by the
unit suite: the cache reads the environment behind std::call_once, so the
enabled path needs a fresh process. This test runs a node in three phases:

1. default (tables off): build a small BLSCT chain with the generic MSM;
2. restart with -blsctfixedbase=1 (small window/prefix so table
   construction stays cheap on CI): the node re-verifies the existing chain
   through the tables on the way up, then extends it with the fast path
   active — every new coinbase range proof is verified through the tables;
3. restart with the tables off again and verifychain: blocks accepted under
   the fast path verify identically under the generic path, pinning the
   bit-for-bit equivalence claim end to end.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


# Fixed-base is ON by default; these args force it on with small tables
# (w=4 over a 64-generator prefix, ~19 MiB, cheap to build in CI while still
# covering every single-output proof, mn = 64). OFF_ARGS forces the generic
# path so both modes are exercised against the same chain.
ON_ARGS = ["-blsctfixedbase=1", "-blsctfixedbasewin=4", "-blsctfixedbaseprefix=64"]
OFF_ARGS = ["-blsctfixedbase=0"]


class BlsctFixedBaseVerifyTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Phase 1: build a BLSCT chain with the generic MSM (fixed-base off)")
        self.restart_node(0, extra_args=OFF_ARGS)
        node.createwallet(wallet_name="w", blsct=True)
        wallet = node.get_wallet_rpc("w")
        addr = wallet.getnewaddress()
        self.generatetoblsctaddress(node, 12, addr)
        assert_equal(node.getblockcount(), 12)
        tip_generic = node.getbestblockhash()

        self.log.info("Phase 2: restart with the fixed-base tables enabled")
        self.stop_node(0)
        self.start_node(0, extra_args=ON_ARGS)
        # The chain built by the generic path loads and the tip is unchanged.
        assert_equal(node.getbestblockhash(), tip_generic)
        # verifychain re-runs block verification -> the tables serve the MSM.
        assert node.verifychain(4, 12)
        # Extend the chain with the fast path active.
        self.generatetoblsctaddress(node, 12, addr)
        assert_equal(node.getblockcount(), 24)
        tip_fixedbase = node.getbestblockhash()

        self.log.info("Phase 3: restart with the tables off and re-verify")
        self.stop_node(0)
        self.start_node(0, extra_args=OFF_ARGS)
        assert_equal(node.getbestblockhash(), tip_fixedbase)
        assert node.verifychain(4, 24)


if __name__ == '__main__':
    BlsctFixedBaseVerifyTest(__file__).main()
