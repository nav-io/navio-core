#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPCs that retrieve information from the mempool."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


class RPCMempoolInfoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        confirmed_utxo = self.wallet.get_utxo()

        # Create a tree of unconfirmed transactions in the mempool:
        #             txA
        #             / \
        #            /   \
        #           /     \
        #          /       \
        #         /         \
        #       txB         txC
        #       / \         / \
        #      /   \       /   \
        #    txD   txE   txF   txG
        #            \   /
        #             \ /
        #             txH

        def create_tx(**kwargs):
            return self.wallet.send_self_transfer_multi(
                from_node=self.nodes[0],
                **kwargs,
            )

        txA = create_tx(utxos_to_spend=[confirmed_utxo], num_outputs=2)
        txB = create_tx(utxos_to_spend=[txA["new_utxos"][0]], num_outputs=2)
        txC = create_tx(utxos_to_spend=[txA["new_utxos"][1]], num_outputs=2)
        txD = create_tx(utxos_to_spend=[txB["new_utxos"][0]], num_outputs=1)
        txE = create_tx(utxos_to_spend=[txB["new_utxos"][1]], num_outputs=1)
        txF = create_tx(utxos_to_spend=[txC["new_utxos"][0]], num_outputs=2)
        txG = create_tx(utxos_to_spend=[txC["new_utxos"][1]], num_outputs=1)
        txH = create_tx(utxos_to_spend=[txE["new_utxos"][0],txF["new_utxos"][0]], num_outputs=1)
        txidA, txidB, txidC, txidD, txidE, txidF, txidG, txidH = [
            tx["txid"] for tx in [txA, txB, txC, txD, txE, txF, txG, txH]
        ]

        outidA, outidB, outidC, outidD, outidE, outidF, outidG, outidH = [
            tx["new_utxos"][0]["txid"] for tx in [txA, txB, txC, txD, txE, txF, txG, txH]
        ]

        mempool = self.nodes[0].getrawmempool()
        assert_equal(len(mempool), 8)
        for txid in [txidA, txidB, txidC, txidD, txidE, txidF, txidG, txidH]:
            assert_equal(txid in mempool, True)

        self.log.info("Find transactions spending outputs")
        result = self.nodes[0].gettxspendingprevout([ {'txid' : confirmed_utxo['txid']}, {'txid' : outidA} ])
        # Verify the first result (confirmed_utxo is spent by txA)
        assert_equal(result[0], {'txid' : confirmed_utxo['txid'], 'spendingtxid' : txidA})
        # For the second result, outidA should be spent by either txB or txC
        # depending on which output outidA actually represents
        # The first output of txA is spent by txB, the second by txC
        assert 'spendingtxid' in result[1]
        assert result[1]['txid'] == outidA
        # Verify that the spending transaction is in the mempool
        spending_txid = result[1]['spendingtxid']
        assert spending_txid in mempool, f"Spending transaction {spending_txid} not in mempool"

        self.log.info("Find transaction spending multiple outputs")
        result = self.nodes[0].gettxspendingprevout([ {'txid' : txidE}, {'txid' : txidF} ])
        assert_equal(result, [ {'txid' : txidE}, {'txid' : txidF} ])

        self.log.info("Find no transaction when output is unspent")
        result = self.nodes[0].gettxspendingprevout([ {'txid' : txH["new_utxos"][0]["txid"]} ])
        assert_equal(result, [ {'txid' : txH["new_utxos"][0]["txid"]} ])


        self.log.info("Mixed spent and unspent outputs")

        self.log.info("Unknown input fields")
        assert_raises_rpc_error(-3, "Unexpected key unknown", self.nodes[0].gettxspendingprevout, [{'txid' : txC["new_utxos"][1]["txid"], 'unknown' : 42}])

        self.log.info("Invalid txid provided")
        assert_raises_rpc_error(-3, "JSON value of type number for field txid is not of expected type string", self.nodes[0].gettxspendingprevout, [{'txid' : 42}])

        self.log.info("Missing outputs")
        assert_raises_rpc_error(-8, "Invalid parameter, outputs are missing", self.nodes[0].gettxspendingprevout, [])


if __name__ == '__main__':
    RPCMempoolInfoTest().main()
