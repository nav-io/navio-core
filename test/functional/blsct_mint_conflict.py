#!/usr/bin/env python3
# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Two individually-valid mints of one capped token must not halt mining.

Mempool validation checks each tx against a fresh view that cannot see other
mempool txs' token side effects, so both mints are accepted. Block assembly
must simulate predicates over the selected txs, exclude the conflicting one,
and still produce a valid template.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlsctMintConflictTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=2):
        blocks = []
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            blocks.extend(self.generatetoblsctaddress(node, to_generate, address))
            remaining -= to_generate
        return blocks

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", blsct=True)
        wallet = node.get_wallet_rpc("w")
        addr = wallet.getnewaddress(label="", address_type="blsct")

        self.log.info("Mining 102 blocks to mature two rewards")
        self.generate_blsct_blocks(node, addr, 102)

        self.log.info("Creating a token with max supply 1 and confirming it")
        token = wallet.createtoken({"name": "conflict"}, 1)
        token_id = token["tokenId"]
        self.generate_blsct_blocks(node, addr, 1)

        self.log.info("Submitting two mints of 1: each is valid against chain state")
        wallet.minttoken(token_id, addr, 1)
        wallet.minttoken(token_id, addr, 1)
        mempool = node.getrawmempool()
        assert_equal(len(mempool), 2)

        self.log.info("A template over both would exceed the cap; mining must still work")
        blocks = node.generatetoblsctaddress(1, addr, invalid_call=False)
        assert_equal(len(blocks), 1)

        # At most one of the two mints can be in the block; the other is now
        # over-cap and must not prevent the next block either.
        blocks = node.generatetoblsctaddress(1, addr, invalid_call=False)
        assert_equal(len(blocks), 1)


if __name__ == '__main__':
    BlsctMintConflictTest(__file__).main()
