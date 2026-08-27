#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Exercise the BLSCT proof transcript v2 activation gate end to end.

The gate (Consensus::nBLSCTProofV2Height) selects the Fiat-Shamir transcript
used to build and verify BLSCT range proofs and set-membership proofs. Below
the height the legacy transcript is used; at and above it, v2. Prover and
verifier both key off the height of the block being produced/checked, so if
they ever disagreed a block across the boundary would be rejected and the
chain could not advance.

This test sets the activation to a low height on blsctregtest via
-blsctproofv2height and mines proof-of-stake blocks (each carries a PoS
kernel range proof + set-membership proof) from below the gate to well above
it, then makes a confidential spend above the gate. Reaching the target
height and confirming the spend proves the prover and verifier agree under
both transcript versions and across the cutover.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class BlsctProofTranscriptV2Test(BitcoinTestFramework):
    ACTIVATION_HEIGHT = 140

    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True
        # Flip the otherwise-dormant gate to a low height so a single regtest
        # run crosses it.
        self.extra_args = [[f"-blsctproofv2height={self.ACTIVATION_HEIGHT}"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=2):
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to_generate, address)
            remaining -= to_generate

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", blsct=True)
        wallet = node.get_wallet_rpc("w")
        addr = wallet.getnewaddress(label="", address_type="blsct")

        # Mine to just below the gate. These PoS blocks are built and verified
        # under the legacy (v1) transcript.
        self.generate_blsct_blocks(node, addr, self.ACTIVATION_HEIGHT - 5)
        height = node.getblockcount()
        assert_greater_than(self.ACTIVATION_HEIGHT, height)
        self.log.info(f"Mined to height {height} (below gate {self.ACTIVATION_HEIGHT}, v1 transcript)")

        # Negative assertion: the gate must NOT be active below the height. This
        # distinguishes "gate fired correctly" from "gate plumbing silently
        # broke and both sides stayed on v1" -- without it, a broken gate passes
        # this test unnoticed.
        gbt = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(gbt.get("pops_transcript_v2"), False)

        # Mine across the boundary and well past it. Every block from
        # ACTIVATION_HEIGHT up is built and verified under v2; if the prover and
        # verifier disagreed at or across the cutover, generatetoblsctaddress
        # would fail or the tip would stall here.
        self.generate_blsct_blocks(node, addr, 20)
        height = node.getblockcount()
        assert_greater_than(height, self.ACTIVATION_HEIGHT)
        self.log.info(f"Mined across gate to height {height} (v2 transcript accepted)")

        # Positive assertion: the gate IS active above the height -- confirms the
        # -blsctproofv2height plumbing actually fired, so the clean cross-boundary
        # mining above is real v2 verification, not two sides silently on v1.
        gbt = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(gbt.get("pops_transcript_v2"), True)

        # A confidential spend built above the gate carries v2 output range
        # proofs. sendtoaddress returning a txid already means the tx passed
        # mempool acceptance (blsct::VerifyTx) under v2; mining it and seeing
        # the mempool drain confirms the block verifier also accepts the v2
        # output proofs. (The on-chain hash of a default aggregate send differs
        # from the returned txid, so assert on mempool drain, not the txid.)
        dest = wallet.getnewaddress(label="", address_type="blsct")
        wallet.sendtoaddress(dest, 1)
        assert_equal(node.getmempoolinfo()["size"], 1)
        self.generate_blsct_blocks(node, addr, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)
        self.log.info(f"v2 confidential spend accepted and mined at height {node.getblockcount()}")

        # Sanity: a full reindex re-verifies every block from genesis, so it
        # re-checks the v1 blocks under v1 and the v2 blocks under v2 by height.
        self.restart_node(0, extra_args=[f"-blsctproofv2height={self.ACTIVATION_HEIGHT}",
                                         "-reindex"])
        assert_equal(node.getblockcount(), height + 1)
        self.log.info("Reindex re-verified the full chain across the gate")


if __name__ == '__main__':
    BlsctProofTranscriptV2Test(__file__).main()
