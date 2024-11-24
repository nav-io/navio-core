#!/usr/bin/env python3
# Copyright (c) 2024 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

class NavioBlsctTokenTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        # Set up two nodes for the test
        self.num_nodes = 2
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def run_test(self):
        self.log.info("Creating wallet1 with BLSCT")
        
        # Create a new wallet
        
        #self.init_wallet(node=0, blsct=True)
        self.nodes[0].createwallet(wallet_name="wallet1", blsct=True)
        self.nodes[1].createwallet(wallet_name="wallet1", blsct=True)
        wallet_info = self.nodes[0].get_wallet_rpc("wallet1")
        wallet_info_2 = self.nodes[1].get_wallet_rpc("wallet1")

        self.log.info("Loading wallet1")
        
        # Ensure wallet is loaded
        wallets = self.nodes[0].listwallets()
        assert "wallet1" in wallets, "wallet1 was not loaded successfully"

        self.log.info("Generating BLSCT address")
        
        # Generate a BLSCT address
        blsct_address = wallet_info.getnewaddress(label="", address_type="blsct")
        blsct_address_2 = wallet_info_2.getnewaddress(label="", address_type="blsct")

        self.log.info(f"BLSCT address NODE 1: {blsct_address}")
        self.log.info(f"BLSCT address NODE 2: {blsct_address_2}")
        
        # Generate blocks and fund the BLSCT address
        self.log.info("Generating 101 blocks to the BLSCT address")
        block_hashes = self.generatetoblsctaddress(self.nodes[0], 101, blsct_address)

        self.log.info(f"Generated blocks: {len(block_hashes)}")
        
        # Check the balance of the wallet
        balance = wallet_info.getbalance()
        self.log.info(f"Balance in wallet1: {balance}")
        
        assert_equal(len(block_hashes), 101)
        assert balance > 0, "Balance should be greater than zero after mining"

        self.log.info("Creating token and mining 1 block")
        token = self.nodes[0].createtoken({"name": "Test"}, 1000)
        block_hashes = self.generatetoblsctaddress(self.nodes[0], 1, blsct_address)

        tokens = self.nodes[0].listtokens()
        assert len(tokens) == 1, "length of tokens is not 1"

        self.log.info(f"Created token: {token['tokenId']}")

        assert tokens[0]['type'] == 'token', "token type is not token"
        assert tokens[0]['metadata'] == {'name': 'Test'}, "incorrect metadata"
        assert tokens[0]['maxSupply'] == 100000000000, "incorrect max supply"
        assert tokens[0]['currentSupply'] == 0, "incorrect current supply"

        self.nodes[0].minttoken(token['tokenId'], blsct_address, 1)
        block_hashes = self.generatetoblsctaddress(self.nodes[0], 1, blsct_address)

        tokenInfo = self.nodes[0].gettoken(token['tokenId'])

        assert tokenInfo['type'] == 'token', "token type is not token"
        assert tokenInfo['metadata'] == {'name': 'Test'}, "incorrect metadata"
        assert tokenInfo['maxSupply'] == 100000000000, "incorrect max supply"
        assert tokenInfo['currentSupply'] == 100000000, "incorrect current supply"

        self.log.info(f"Minted 1 token")

        token_balance = self.nodes[0].gettokenbalance(token['tokenId'])
        token_balance_2 = self.nodes[1].gettokenbalance(token['tokenId'])

        self.log.info(f"Balance in NDOE 1: {token_balance}")
        self.log.info(f"Balance in NODE 2: {token_balance_2}")
        
        assert token_balance == 1, "incorrect token balance in node 1"
        assert token_balance_2 == 0, "incorrect token balance in node 2"

        self.log.info(f"Sending 0.5 token to NODE 2")

        self.nodes[0].sendtokentoblsctaddress(token['tokenId'], blsct_address_2, 0.5)
        self.generatetoblsctaddress(self.nodes[0], 2, blsct_address)

        token_balance = self.nodes[0].gettokenbalance(token['tokenId'])
        token_balance_2 = self.nodes[1].gettokenbalance(token['tokenId'])

        assert token_balance == 0.5, "incorrect token balance in node 1"
        assert token_balance_2 == 0.5, "incorrect token balance in node 2"

        self.log.info(f"Balance in NDOE 1: {token_balance}")
        self.log.info(f"Balance in NODE 2: {token_balance_2}")


if __name__ == '__main__':
    NavioBlsctTokenTest().main()
