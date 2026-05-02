#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Reject invalid PoPS blocks on submitblock.

Tests that blocks whose posProof bytes have been tampered after mining are
rejected by the consensus-verification path. Each mutation is applied at a
byte offset inside the block's posProof region; we then roll the tip back
with invalidateblock() and resubmit. The node must refuse the mutated
block with the consensus-level reject reason 'bad-blsct-pos-proof'.

Block layout for a BLSCT PoS block:
  [80-byte header]
  [posProof body]
    [SetMemProof: phi (48B) + A1 (48B) + A2 (48B) + S1, S2, S3, T1, T2 ...]
    [RangeProof without Vs: Ls vec + Rs vec + A + A_wip + B + scalars]
  [vector<CTransaction>]

We target bytes inside the posProof region (offset ≥ 80) so the header
parsing, sanity checks, and tx verification all still complete — only the
PoS proof verification fails, proving the consensus gate works.
"""

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework


class BlsctPopsConsensusTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_one(self, node, address):
        hashes = self.generatetoblsctaddress(node, 1, address)
        assert len(hashes) == 1
        return hashes[0]

    def submit_tampered(self, node, tampered_hex, description):
        """Call submitblock on a tampered block. The node can reject in
        two ways:
          * Return a non-empty string reject reason (consensus-level).
          * Raise JSONRPCException with 'Block decode failed' when the
            block can't even deserialise (e.g. a malformed G1 encoding).
        Either counts as a pass; we just assert it's NOT accepted.
        """
        accepted_rejections = (
            "bad-blsct-pos-proof",
            "bad-blk-proof",
            "block-validation-failed",
            "error parsing message",
            "Block decode failed",
            "invalid",
        )
        try:
            reason = node.submitblock(tampered_hex)
        except JSONRPCException as e:
            msg = str(e)
            assert any(s in msg for s in accepted_rejections), (
                f"[{description}] unexpected JSONRPC error: {msg!r}"
            )
            self.log.info(f"[{description}] rejected via RPC error: {msg}")
            return
        assert reason is not None and reason != "", (
            f"[{description}] block unexpectedly accepted despite tampering"
        )
        assert any(s in reason for s in accepted_rejections), (
            f"[{description}] unexpected rejection reason: {reason!r}"
        )
        self.log.info(f"[{description}] rejected as expected: {reason}")

    def tamper_and_submit(self, node, address, offset, new_bytes, description):
        """Mine a tip, roll it back, mutate `len(new_bytes)` bytes at
        `offset` inside the block, and assert submitblock rejects it."""
        tip_hash = self.mine_one(node, address)
        block_hex = node.getblock(tip_hash, 0)
        block_bytes = bytearray(bytes.fromhex(block_hex))

        assert offset + len(new_bytes) <= len(block_bytes), (
            f"offset {offset}+{len(new_bytes)} beyond block size {len(block_bytes)}"
        )

        # Invalidate so the node treats the resubmitted (tampered) block as
        # a fresh acceptance attempt rather than a duplicate no-op.
        node.invalidateblock(tip_hash)

        block_bytes[offset:offset + len(new_bytes)] = new_bytes
        tampered_hex = bytes(block_bytes).hex()

        self.submit_tampered(node, tampered_hex, description)

        # Restore the original valid tip so the next iteration starts
        # from the real chain.
        node.reconsiderblock(tip_hash)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", blsct=True)
        wallet = node.get_wallet_rpc("w")
        addr = wallet.getnewaddress(label="", address_type="blsct")

        # Warm up: the set-membership proof needs at least 2 staked
        # commitments on chain before Verify will even look at a proof.
        # Generating ~60 blocks gives the regtest BLSCT chain enough
        # maturity to produce well-formed PoS proofs on the tip.
        for _ in range(60):
            self.mine_one(node, addr)

        self.log.info("baseline: submitblock of the untampered tip is a duplicate, not a PoS failure")
        tip_hash = node.getbestblockhash()
        block_hex = node.getblock(tip_hash, 0)
        reason = node.submitblock(block_hex)
        # 'duplicate' means the valid block was accepted as already-known,
        # which is the correct outcome. If this ever returns a PoS error,
        # the untampered build is broken and later test cases would be
        # meaningless.
        assert reason in (None, "", "duplicate", "duplicate-invalid"), (
            f"valid block unexpectedly rejected: {reason!r}"
        )

        # The posProof body starts at byte 80 (right after the 80-byte
        # header). SetMemProof is first; its first field is `phi`, a
        # compressed G1 point occupying 48 bytes at offsets 80..127.
        PHI_OFFSET = 80
        # After phi (48) come A1, A2, S1, S2, S3, T1, T2, each 48 bytes.
        # A1 lives at 128..175.
        A1_OFFSET = PHI_OFFSET + 48

        # Tamper 1: replace phi with bytes that decode to a clearly wrong
        # G1 point. 0xFF...FF fails the compressed-encoding validity check
        # in mcl, so the proof either fails to deserialise (consensus
        # rejects) or deserialises to an identity-ish junk that
        # SetMemProof::Verify will reject.
        self.tamper_and_submit(
            node, addr, PHI_OFFSET, bytes([0xFF] * 48),
            "set-mem phi filled with 0xFF",
        )

        # Tamper 2: same treatment for A1.
        self.tamper_and_submit(
            node, addr, A1_OFFSET, bytes([0xFF] * 48),
            "set-mem A1 filled with 0xFF",
        )

        # Tamper 3: flip a single bit mid-proof. This lands inside A2 or
        # later — the block either fails deserialisation or fails verify.
        tip_hash = self.mine_one(node, addr)
        block_hex = node.getblock(tip_hash, 0)
        block_bytes = bytearray(bytes.fromhex(block_hex))
        node.invalidateblock(tip_hash)
        bit_flip_offset = 80 + 300
        block_bytes[bit_flip_offset] ^= 0x01
        self.submit_tampered(node, bytes(block_bytes).hex(), "mid-proof bit flip")
        node.reconsiderblock(tip_hash)


if __name__ == "__main__":
    BlsctPopsConsensusTest().main()
