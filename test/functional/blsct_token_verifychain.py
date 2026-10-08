#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""verifychain at level 4 over blocks that create and then mint tokens.

Level 4 disconnects the checked blocks into one coins cache and reconnects
them into that same cache. Disconnecting a create-token block erases the
token there; reconnecting it has to bring the token back, or a mint in a
later checked block finds no token and the block is reported unconnectable.
Covers a fungible token and an NFT collection, then the same check at
startup through -checklevel=4.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlsctTokenVerifyChainTest(BitcoinTestFramework):
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
        node.createwallet(wallet_name="w", blsct=True)
        wallet = node.get_wallet_rpc("w")
        addr = wallet.getnewaddress(label="", address_type="blsct")
        self.generatetoblsctaddress(node, 101, addr)
        start_height = node.getblockcount()

        self.log.info("Create a token and an NFT collection, then mint both in a later block")
        token_id = wallet.createtoken({"name": "Verify"}, 1000)['tokenId']
        nft_id = wallet.createnft({"name": "VerifyNft"}, 10)['tokenId']
        self.generatetoblsctaddress(node, 1, addr)
        wallet.minttoken(token_id, addr, 1)
        self.generatetoblsctaddress(node, 1, addr)
        wallet.mintnft(nft_id, 1, addr, {"id": "1"})
        self.generatetoblsctaddress(node, 1, addr)
        assert_equal(node.gettoken(token_id)['currentSupply'], 100000000)

        checked = node.getblockcount() - start_height + 1
        self.log.info(f"verifychain level 4 over the last {checked} blocks")
        assert node.verifychain(4, checked)

        self.log.info("Startup verification at -checklevel=4 covers the same blocks")
        self.restart_node(0, extra_args=["-checklevel=4", f"-checkblocks={checked}"])
        assert_equal(node.gettoken(token_id)['currentSupply'], 100000000)


if __name__ == '__main__':
    BlsctTokenVerifyChainTest(__file__).main()
