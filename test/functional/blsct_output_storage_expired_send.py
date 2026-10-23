#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A send from an output-storage wallet that expires from the mempool.

Regression for issue #511. The wallet holds exactly one confirmed coin and
sends from it; the send then expires from the mempool (-mempoolexpiry) without
being mined. The wallet must stop treating the send as in the mempool: its
change leaves the trusted balance and the coin set, while the spent coin stays
spent. abandontransaction must then accept the send and give the coin back,
and a new send must be able to spend it.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

EXPIRY_HOURS = 1
FUNDING_AMOUNT = Decimal("100")
SEND_AMOUNT = Decimal("1")


class BlsctOutputStorageExpiredSendTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [[f"-mempoolexpiry={EXPIRY_HOURS}"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def trusted(self, wallet):
        return Decimal(str(wallet.getbalances()["mine"]["trusted"]))

    def unspent(self, wallet):
        return sorted((u["outid"], Decimal(str(u["amount"]))) for u in wallet.listblsctunspent(0))

    def send(self, wallet, address, amount):
        """Send and return the txid of the transaction it put in the mempool."""
        node = self.nodes[0]
        before = set(node.getrawmempool())
        wallet.sendtoblsctaddress(address, amount)
        node.syncwithvalidationinterfacequeue()
        added = set(node.getrawmempool()) - before
        assert_equal(len(added), 1)
        return added.pop()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="miner", blsct=True, storage_output=True)
        node.createwallet(wallet_name="sender", blsct=True, storage_output=True)
        miner = node.get_wallet_rpc("miner")
        sender = node.get_wallet_rpc("sender")
        miner_addr = miner.getnewaddress(label="", address_type="blsct")
        sender_addr = sender.getnewaddress(label="", address_type="blsct")

        self.log.info("Fund the sender with exactly one confirmed coin")
        for _ in range(51):
            self.generatetoblsctaddress(node, 4, miner_addr)
        self.send(miner, sender_addr, FUNDING_AMOUNT)
        self.generatetoblsctaddress(node, 1, miner_addr)
        coin = self.unspent(sender)
        assert_equal([amount for _, amount in coin], [FUNDING_AMOUNT])

        self.log.info("Send from it and let the send expire from the mempool")
        txid = self.send(sender, miner_addr, SEND_AMOUNT)
        change = self.trusted(sender)
        assert 0 < change < FUNDING_AMOUNT - SEND_AMOUNT
        assert_raises_rpc_error(-5, "Transaction not eligible for abandonment", sender.abandontransaction, txid)

        entry_time = node.getmempoolentry(txid)["time"]
        node.setmocktime(entry_time + EXPIRY_HOURS * 60 * 60 + 5)
        # Expiry is only checked when a transaction enters the mempool.
        self.send(miner, miner_addr, SEND_AMOUNT)
        assert txid not in node.getrawmempool()
        node.syncwithvalidationinterfacequeue()

        self.log.info("The expired send is no longer trusted, its input stays spent")
        assert_equal(self.trusted(sender), 0)
        assert_equal(self.unspent(sender), [])
        assert_equal(sender.gettransaction(txid)["trusted"], False)

        self.log.info("abandontransaction gives the coin back")
        sender.abandontransaction(txid)
        assert_equal(self.unspent(sender), coin)
        assert_equal(self.trusted(sender), FUNDING_AMOUNT)

        self.log.info("A new send spends the recovered coin")
        new_txid = self.send(sender, miner_addr, SEND_AMOUNT)
        self.generatetoblsctaddress(node, 1, miner_addr)
        assert_equal(sender.gettransaction(new_txid)["confirmations"], 1)
        assert 0 < self.trusted(sender) < FUNDING_AMOUNT - SEND_AMOUNT


if __name__ == "__main__":
    BlsctOutputStorageExpiredSendTest(__file__).main()
