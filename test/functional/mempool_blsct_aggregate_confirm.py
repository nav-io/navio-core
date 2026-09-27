#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mempool transactions merged into a block's aggregate leave as confirmed.

A BLSCT block carries a coinbase plus a single aggregate transaction built
from the selected mempool transactions, so the block never contains their
txids. The mempool recognises a transaction whose inputs are all spent by
the block and whose (non-fee) outputs are all created by it as confirmed:
it leaves with its in-mempool descendants kept, and the fee estimator counts
it as a confirmation.
"""

from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

NUM_PARENTS = 3
UTXO_AMOUNT = Decimal("10")
SEND_AMOUNT = Decimal("4")


class MempoolBlsctAggregateConfirmTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [["-debug=estimatefee"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine(self, address, n=1):
        blocks = []
        for _ in range(n):
            blocks.extend(self.generatetoblsctaddress(self.nodes[0], 1, address))
        return blocks

    def send(self, wallet, address, amount):
        """Send and return the new transaction's txid (the send RPC returns
        the recipient's output hash)."""
        before = set(self.nodes[0].getrawmempool())
        wallet.sendtoblsctaddress(address, amount)
        new = set(self.nodes[0].getrawmempool()) - before
        assert_equal(len(new), 1)
        return new.pop()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="funder", blsct=True, storage_output=True)
        node.createwallet(wallet_name="sender", blsct=True, storage_output=True)
        funder = node.get_wallet_rpc("funder")
        sender = node.get_wallet_rpc("sender")

        miner_addr = funder.getnewaddress(label="", address_type="blsct")
        self.mine(miner_addr, 110)

        self.log.info("Give the sender one confirmed output per parent send")
        for _ in range(NUM_PARENTS):
            funder.sendtoblsctaddress(sender.getnewaddress(label="", address_type="blsct"), UTXO_AMOUNT)
            self.mine(miner_addr)
        assert_equal(len(sender.listblsctunspent()), NUM_PARENTS)

        self.log.info("Create independent parents and a child spending unconfirmed change")
        dest = funder.getnewaddress(label="", address_type="blsct")
        parents = [self.send(sender, dest, SEND_AMOUNT) for _ in range(NUM_PARENTS)]
        # Every confirmed output is spent now, so this spends a parent's change.
        child = self.send(sender, dest, Decimal("1"))
        mempool = node.getrawmempool(True)
        assert_equal(set(mempool), set(parents + [child]))
        assert mempool[child]["ancestorcount"] >= 2

        # Keep the child out of the next block so only its parent is merged.
        node.prioritisetransaction(txid=child, fee_delta=-COIN)

        self.log.info("Mine a block aggregating the parents")
        with node.assert_debug_log(expected_msgs=[f"Blockpolicy estimates updated by {NUM_PARENTS} of {NUM_PARENTS} block txs"]):
            block_hash = self.mine(miner_addr)[0]
        block = node.getblock(block_hash)
        assert_equal(len(block["tx"]), 2)
        for txid in parents:
            assert txid not in block["tx"]
            assert_raises_rpc_error(-5, "Transaction not in mempool", node.getmempoolentry, txid)

        self.log.info("The child stays, now without in-mempool ancestors")
        assert_equal(node.getrawmempool(), [child])
        entry = node.getmempoolentry(child)
        assert_equal(entry["ancestorcount"], 1)
        assert_equal(entry["depends"], [])

        self.log.info("The wallet sees the parents as confirmed")
        for txid in parents:
            assert_equal(sender.gettransaction(txid)["confirmations"], 1)

        self.log.info("The child confirms in the following block")
        node.prioritisetransaction(txid=child, fee_delta=COIN)
        self.mine(miner_addr)
        assert_equal(node.getrawmempool(), [])


if __name__ == "__main__":
    MempoolBlsctAggregateConfirmTest(__file__).main()
