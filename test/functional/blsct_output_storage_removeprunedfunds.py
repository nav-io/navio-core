#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""removeprunedfunds must forget a send in an output-storage wallet too.

removeprunedfunds deletes a transaction from the wallet as if it had never
been seen. For a send that has two consequences, both visible in a full-tx
wallet:

* the send's own outputs (its change) are no longer the wallet's, and
* the coin it spent is no longer spent by anything the wallet knows of. The
  funding transaction is still in the wallet, so that coin is reported as
  unspent again -- the wallet has simply lost track of the spend.

A wallet with WALLET_FLAG_BLSCT_OUTPUT_STORAGE records a local send both as a
CWalletTx and in its per-output records: the change gets an output row and the
spent coin's row is marked spent by the send. Forgetting the send has to undo
both records, in memory and on disk, or the wallet keeps counting change it no
longer has a transaction for and keeps the funding coin spent by a transaction
it no longer has.

A full-tx wallet doing the same thing is the control: both must end up holding
exactly the funding coin, before and after a restart.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

FUND_AMOUNT = Decimal("500.00000000")
SEND_AMOUNT = Decimal("120.00000000")


def to_dec(value):
    return Decimal(str(value))


class BlsctOutputStorageRemovePrunedFundsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, address, num_blocks, batch_size=2):
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            self.generatetoblsctaddress(self.nodes[0], to_generate, address)
            remaining -= to_generate

    def assert_holds_only(self, wallet, outid, scenario):
        """`wallet` holds exactly the coin `outid`, unspent, worth FUND_AMOUNT."""
        mine = wallet.getbalances()["mine"]
        unspent = wallet.listblsctunspent(0, 9999999)
        self.log.info(f"[{scenario}] getbalances.mine={mine} listblsctunspent="
                      f"{[(u['outid'], u['amount']) for u in unspent]}")
        assert_equal(to_dec(mine["trusted"]), FUND_AMOUNT)
        assert_equal(to_dec(mine["untrusted_pending"]), Decimal("0"))
        assert_equal(to_dec(wallet.getblsctbalance()), FUND_AMOUNT)
        assert_equal([(u["outid"], to_dec(u["amount"])) for u in unspent],
                     [(outid, FUND_AMOUNT)])

    def fund_send_and_forget(self, storage_output):
        """Fund a fresh wallet, send from it with change, mine the send, then
        removeprunedfunds it. Returns (wallet name, funding coin outid)."""
        node = self.nodes[0]
        name = f"zap_storage_{int(storage_output)}"
        node.createwallet(wallet_name=name, blsct=True, storage_output=storage_output)
        wallet = node.get_wallet_rpc(name)
        addr = wallet.getnewaddress(label="", address_type="blsct")

        self.miner.sendtoblsctaddress(addr, FUND_AMOUNT)
        self.generate_blsct_blocks(self.miner_addr, 1)
        unspent = wallet.listblsctunspent(0, 9999999)
        assert_equal(len(unspent), 1)
        funding_outid = unspent[0]["outid"]
        self.assert_holds_only(wallet, funding_outid, f"storage={storage_output} funded")

        wallet.sendtoblsctaddress(self.receiver_addr, SEND_AMOUNT)
        self.generate_blsct_blocks(self.miner_addr, 1)
        sends = [e for e in wallet.listtransactions("*", 10 ** 9, 0, True)
                 if e.get("category") == "send"]
        assert_equal(len(sends), 1)
        send_txid = sends[0]["txid"]
        # Before the zap the change is the only coin, and the funding coin is
        # spent.
        unspent = wallet.listblsctunspent(0, 9999999)
        assert_equal(len(unspent), 1)
        assert unspent[0]["outid"] != funding_outid
        change = to_dec(unspent[0]["amount"])
        assert change < FUND_AMOUNT - SEND_AMOUNT
        assert_equal(to_dec(wallet.getbalances()["mine"]["trusted"]), change)

        wallet.removeprunedfunds(send_txid)
        self.assert_holds_only(wallet, funding_outid, f"storage={storage_output} zapped")
        return name, funding_outid

    def run_test(self):
        node = self.nodes[0]

        node.createwallet(wallet_name="miner", blsct=True)
        self.miner = node.get_wallet_rpc("miner")
        self.miner_addr = self.miner.getnewaddress(label="", address_type="blsct")
        node.createwallet(wallet_name="receiver", blsct=True)
        self.receiver_addr = node.get_wallet_rpc("receiver").getnewaddress(label="", address_type="blsct")
        self.generate_blsct_blocks(self.miner_addr, 101)

        self.log.info("Control: removeprunedfunds of a send in a full-tx wallet")
        control = self.fund_send_and_forget(storage_output=False)

        self.log.info("removeprunedfunds of a send in an output-storage wallet")
        storage = self.fund_send_and_forget(storage_output=True)

        self.log.info("Both wallets still hold only the funding coin after a restart")
        self.restart_node(0)
        for name, outid in (control, storage):
            node.loadwallet(name)
            self.assert_holds_only(node.get_wallet_rpc(name), outid, f"{name} restarted")


if __name__ == '__main__':
    BlsctOutputStorageRemovePrunedFundsTest(__file__).main()
