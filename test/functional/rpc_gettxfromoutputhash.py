#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test the gettxfromoutputhash RPC command."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class GetTxFromOutputHashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-txindex"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        # Generate some blocks to have a base
        self.generate(wallet, 101)

        # Create a transaction with outputs
        tx_result = wallet.send_self_transfer(from_node=node)
        txid = tx_result['txid']

        # Mine a block to confirm the transaction
        self.generate(wallet, 1)

        # Get the transaction details to find an output hash
        tx_details = node.getrawtransaction(txid, True)

        # Find the first output and get its hash
        first_output = tx_details['vout'][0]
        output_hash = first_output['hash']

        # Test the new RPC command
        result = node.gettxfromoutputhash(output_hash)

        # Verify the result
        assert_equal(result['txid'], txid)
        assert_equal(result['vout'], 0)
        assert_equal(result['confirmations'], 1)  # Should be confirmed
        assert 'blockhash' in result

        # Test with a non-existent output hash
        fake_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        assert_raises_rpc_error(
            -5,  # RPC_INVALID_ADDRESS_OR_KEY
            "Output hash not found in blockchain or mempool",
            node.gettxfromoutputhash,
            fake_hash
        )

        # Test with mempool transaction
        # Create a new transaction but don't mine it
        mempool_tx_result = wallet.send_self_transfer(from_node=node)
        mempool_txid = mempool_tx_result['txid']

        # Get the transaction details
        mempool_tx_details = node.getrawtransaction(mempool_txid, True)
        mempool_output_hash = mempool_tx_details['vout'][0]['hash']

        # Test finding the mempool transaction
        mempool_result = node.gettxfromoutputhash(mempool_output_hash)
        assert_equal(mempool_result['txid'], mempool_txid)
        assert_equal(mempool_result['vout'], 0)
        assert_equal(mempool_result['confirmations'], 0)  # Should be unconfirmed
        assert 'blockhash' not in mempool_result

        # Test with include_mempool=false
        assert_raises_rpc_error(
            -5,  # RPC_INVALID_ADDRESS_OR_KEY
            "Output hash not found in blockchain or mempool",
            node.gettxfromoutputhash,
            mempool_output_hash,
            False  # include_mempool=False
        )


if __name__ == '__main__':
    GetTxFromOutputHashTest().main()
