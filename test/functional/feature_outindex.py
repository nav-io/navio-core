#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test -outindex: getoutputinfo, gettxfromoutputhash through the index, reorgs
and building the index for an existing chain."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

FAKE_HASH = "11" * 32


class OutIndexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-outindex"], []]

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.generate(self.wallet, 101)

        self.log.info("A confirmed, unspent output reports where it was created")
        tx_a = self.wallet.send_self_transfer(from_node=node)
        block_a = self.generate(self.wallet, 1)[0]
        out_a = tx_a['new_utxo']['txid']
        info = node.getoutputinfo(out_a)
        assert_equal(info['txid'], tx_a['txid'])
        assert_equal(info['vout'], 0)
        assert_equal(info['blockhash'], block_a)
        assert_equal(info['height'], 102)
        assert_equal(info['confirmations'], 1)
        assert_equal(info['spent'], False)
        assert 'spentby' not in info

        self.log.info("A spend in a block is recorded on the spent output")
        tx_b = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=tx_a['new_utxo'])
        block_b = self.generate(self.wallet, 1)[0]
        out_b = tx_b['new_utxo']['txid']
        info = node.getoutputinfo(out_a)
        assert_equal(info['spent'], True)
        assert_equal(info['confirmations'], 2)
        assert_equal(info['spentby'], {'txid': tx_b['txid'], 'vin': 0, 'blockhash': block_b, 'height': 103})

        self.log.info("gettxfromoutputhash answers spent outputs from the index")
        result = node.gettxfromoutputhash(out_a)
        assert_equal(result, {'txid': tx_a['txid'], 'vout': 0, 'blockhash': block_a, 'confirmations': 2})
        # Same answer as the node without the index, which has to scan.
        self.sync_all()
        assert_equal(self.nodes[1].gettxfromoutputhash(out_a), result)

        self.log.info("Unknown outputs are reported as not found")
        assert_raises_rpc_error(-5, "Output hash not found in blockchain", node.getoutputinfo, FAKE_HASH)
        assert_raises_rpc_error(-5, "Output hash not found in blockchain or mempool", node.gettxfromoutputhash, FAKE_HASH)

        self.log.info("A reorg drops the disconnected block's outputs and spends")
        node.invalidateblock(block_b)
        # tx_b went back to the mempool; replace block_b with two blocks that
        # leave it out.
        self.generateblock(node, output=self.wallet.get_address(), transactions=[], sync_fun=self.no_op)
        self.generateblock(node, output=self.wallet.get_address(), transactions=[], sync_fun=self.no_op)
        info = node.getoutputinfo(out_a)
        assert_equal(info['spent'], False)
        assert 'spentby' not in info
        assert_raises_rpc_error(-5, "Output hash not found in blockchain", node.getoutputinfo, out_b)
        # The mempool copy of tx_b is still found with include_mempool.
        assert_equal(node.gettxfromoutputhash(out_b)['confirmations'], 0)
        assert_raises_rpc_error(-5, "Output hash not found in blockchain or mempool",
                                node.gettxfromoutputhash, out_b, False)

        self.log.info("Mining the spend again records it at its new height")
        block_b2 = self.generate(self.wallet, 1, sync_fun=self.no_op)[0]
        info = node.getoutputinfo(out_a)
        assert_equal(info['spentby'], {'txid': tx_b['txid'], 'vin': 0, 'blockhash': block_b2, 'height': 105})
        assert_equal(node.getoutputinfo(out_b)['blockhash'], block_b2)
        self.sync_blocks()

        self.log.info("Without -outindex getoutputinfo is unavailable")
        assert_raises_rpc_error(-1, "Requires -outindex", self.nodes[1].getoutputinfo, out_a)

        self.log.info("Enabling -outindex on an existing chain builds the same index")
        self.restart_node(1, extra_args=["-outindex"])
        self.wait_until(lambda: self.nodes[1].getindexinfo("outindex")["outindex"]["synced"])
        for out in (out_a, out_b):
            assert_equal(self.nodes[1].getoutputinfo(out), node.getoutputinfo(out))

        self.log.info("-outindex is incompatible with pruning")
        self.stop_node(1)
        self.nodes[1].assert_start_raises_init_error(
            extra_args=["-outindex", "-prune=550"],
            expected_msg="Error: Prune mode is incompatible with -outindex.")


if __name__ == '__main__':
    OutIndexTest(__file__).main()
