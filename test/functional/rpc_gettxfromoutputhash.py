#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test the gettxfromoutputhash RPC command."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

NOT_FOUND_ERROR = "Output hash not found in blockchain or mempool"
PRUNED_ERROR = "Output hash not found in unpruned blocks (pruned data)"

# Height the pruning node is asked to prune up to, and the height its chain is
# mined to first. pruneblockchain() refuses to prune within 288 blocks of the
# tip, and -fastprune keeps the block files small enough that a regtest chain
# spans several of them, so pruning actually unlinks something.
PRUNE_HEIGHT = 600
PRUNED_NODE_CHAIN_HEIGHT = 800


class GetTxFromOutputHashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-txindex"], ["-fastprune", "-prune=1"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        # Generate some blocks to have a base
        self.generate(wallet, 101)

        # MiniWallet reports the output hash of a created output as the utxo's
        # 'txid' (an outpoint on this chain is a bare output hash) and the
        # containing transaction's hash as 'transaction_txid'.
        tx_a = wallet.send_self_transfer(from_node=node)
        block_a = self.generate(wallet, 1)[0]
        self.generate(wallet, 5)
        output_hash_a = tx_a['new_utxo']['txid']

        self.log.info("Confirmed, unspent output resolves from the UTXO set")
        result = node.gettxfromoutputhash(output_hash_a)
        assert_equal(result['txid'], tx_a['txid'])
        assert_equal(result['vout'], 0)
        assert_equal(result['blockhash'], block_a)
        assert_equal(result['confirmations'], 6)

        self.log.info("Confirmed, confirmed-spent output still resolves")
        # Spending output A in a block removes it from the UTXO set, so this
        # lookup can only be answered by the backwards scan over the chain.
        tx_b = wallet.send_self_transfer(from_node=node, utxo_to_spend=tx_a['new_utxo'])
        block_b = self.generate(wallet, 1)[0]
        output_hash_b = tx_b['new_utxo']['txid']

        spent_result = node.gettxfromoutputhash(output_hash_a)
        assert_equal(spent_result['txid'], tx_a['txid'])
        assert_equal(spent_result['vout'], 0)
        assert_equal(spent_result['blockhash'], block_a)
        assert_equal(spent_result['confirmations'], 7)

        result_b = node.gettxfromoutputhash(output_hash_b)
        assert_equal(result_b['txid'], tx_b['txid'])
        assert_equal(result_b['blockhash'], block_b)
        assert_equal(result_b['confirmations'], 1)

        self.log.info("Output spent only in the mempool still resolves to its block")
        # Output B stays in the UTXO set while its spend is unconfirmed, so it
        # must still report the block that created it.
        tx_c = wallet.send_self_transfer(from_node=node, utxo_to_spend=tx_b['new_utxo'])
        output_hash_c = tx_c['new_utxo']['txid']

        result_b = node.gettxfromoutputhash(output_hash_b)
        assert_equal(result_b['txid'], tx_b['txid'])
        assert_equal(result_b['blockhash'], block_b)
        assert_equal(result_b['confirmations'], 1)

        self.log.info("Mempool output resolves with zero confirmations")
        mempool_result = node.gettxfromoutputhash(output_hash_c)
        assert_equal(mempool_result['txid'], tx_c['txid'])
        assert_equal(mempool_result['vout'], 0)
        assert_equal(mempool_result['confirmations'], 0)
        assert 'blockhash' not in mempool_result

        # Test with include_mempool=false
        assert_raises_rpc_error(
            -5,  # RPC_INVALID_ADDRESS_OR_KEY
            NOT_FOUND_ERROR,
            node.gettxfromoutputhash,
            output_hash_c,
            False  # include_mempool=False
        )

        self.log.info("Unknown output hash is reported as not found")
        fake_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        assert_raises_rpc_error(
            -5,  # RPC_INVALID_ADDRESS_OR_KEY
            NOT_FOUND_ERROR,
            node.gettxfromoutputhash,
            fake_hash
        )

        self.test_pruned_node(wallet, output_hash_a, output_hash_b)

    def test_pruned_node(self, wallet, spent_output_hash, unspent_output_hash):
        self.log.info("Pruned blocks are reported as pruned, not as not found")
        node = self.nodes[0]
        pruned_node = self.nodes[1]

        while node.getblockcount() < PRUNED_NODE_CHAIN_HEIGHT:
            self.generate(wallet, min(250, PRUNED_NODE_CHAIN_HEIGHT - node.getblockcount()))

        # pruneblockchain() unlinks whole block files, so it stops at the file
        # boundary below the requested height and reports where it got to.
        assert pruned_node.pruneblockchain(PRUNE_HEIGHT) > 0
        # Confirm the blocks holding the two outputs really were pruned away,
        # otherwise the assertions below would pass on unpruned blocks.
        for output_hash in (spent_output_hash, unspent_output_hash):
            blockhash = node.gettxfromoutputhash(output_hash)['blockhash']
            assert_raises_rpc_error(-1, "Block not available (pruned data)",
                                    pruned_node.getblock, blockhash)

        # A spent output reaches the pruned blocks through the backwards scan,
        # an unspent one through its UTXO set entry. Neither may claim the
        # output does not exist.
        assert_raises_rpc_error(-1, PRUNED_ERROR, pruned_node.gettxfromoutputhash, spent_output_hash)
        assert_raises_rpc_error(-1, PRUNED_ERROR, pruned_node.gettxfromoutputhash, unspent_output_hash)

        self.log.info("Pruned node still resolves outputs in the blocks it kept")
        tx = wallet.send_self_transfer(from_node=node)
        blockhash = self.generate(wallet, 1)[0]
        result = pruned_node.gettxfromoutputhash(tx['new_utxo']['txid'])
        assert_equal(result['txid'], tx['txid'])
        assert_equal(result['vout'], 0)
        assert_equal(result['blockhash'], blockhash)
        assert_equal(result['confirmations'], 1)


if __name__ == '__main__':
    GetTxFromOutputHashTest(__file__).main()
