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

When the staker merges the send with another into one block transaction under a
different hash, that transaction spent the funding coin and created the change
on chain. Forgetting the local send must then leave both as they are: the
funding coin stays spent and the change stays held. (A full-tx wallet has no
counterpart: it replaces the local send with the block transaction as soon as
the block connects.)

If that block is disconnected when the send is forgotten, the merged
transaction is back in the mempool and the change is no longer confirmed, so
the change row goes with the send. Reconnecting the block must restore it.

A change row kept or restored this way is an ordinary coin: a later send can
spend it.
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

    def merge_send_and_forget(self):
        """Fund a fresh output-storage wallet, mine its send in one block with
        a send of the miner's so the two are merged, then removeprunedfunds
        the local send. Returns (wallet name, change outid, change amount)."""
        node = self.nodes[0]
        name = "zap_storage_merged"
        node.createwallet(wallet_name=name, blsct=True, storage_output=True)
        wallet = node.get_wallet_rpc(name)
        addr = wallet.getnewaddress(label="", address_type="blsct")

        self.miner.sendtoblsctaddress(addr, FUND_AMOUNT)
        self.generate_blsct_blocks(self.miner_addr, 1)
        funding_outid = wallet.listblsctunspent(0, 9999999)[0]["outid"]

        wallet.sendtoblsctaddress(self.receiver_addr, SEND_AMOUNT)
        self.miner.sendtoblsctaddress(self.receiver_addr, SEND_AMOUNT)
        mempool = node.getrawmempool()
        assert_equal(len(mempool), 2)
        sends = [e for e in wallet.listtransactions("*", 10 ** 9, 0, True)
                 if e.get("category") == "send"]
        assert_equal(len(sends), 1)
        send_txid = sends[0]["txid"]
        assert send_txid in mempool
        block_hash = self.generatetoblsctaddress(node, 1, self.miner_addr)[0]
        assert_equal(node.getrawmempool(), [])
        assert send_txid not in node.getblock(block_hash)["tx"], "send was not merged"

        unspent = wallet.listblsctunspent(0, 9999999)
        assert_equal(len(unspent), 1)
        change_outid = unspent[0]["outid"]
        change = to_dec(unspent[0]["amount"])
        assert change_outid != funding_outid
        assert change < FUND_AMOUNT - SEND_AMOUNT

        wallet.removeprunedfunds(send_txid)
        self.assert_holds_change(wallet, change_outid, change, "merged zapped")
        return name, change_outid, change

    def merge_disconnect_and_forget(self):
        """Merge a fresh output-storage wallet's send into a block transaction,
        disconnect that block so the merged transaction is back in the mempool,
        removeprunedfunds the local send, then reconnect the block. Returns
        (wallet name, change outid, change amount)."""
        node = self.nodes[0]
        name = "zap_storage_merged_unconfirmed"
        node.createwallet(wallet_name=name, blsct=True, storage_output=True)
        wallet = node.get_wallet_rpc(name)
        addr = wallet.getnewaddress(label="", address_type="blsct")

        self.miner.sendtoblsctaddress(addr, FUND_AMOUNT)
        self.generate_blsct_blocks(self.miner_addr, 1)
        funding_outid = wallet.listblsctunspent(0, 9999999)[0]["outid"]

        wallet.sendtoblsctaddress(self.receiver_addr, SEND_AMOUNT)
        self.miner.sendtoblsctaddress(self.receiver_addr, SEND_AMOUNT)
        sends = [e for e in wallet.listtransactions("*", 10 ** 9, 0, True)
                 if e.get("category") == "send"]
        assert_equal(len(sends), 1)
        send_txid = sends[0]["txid"]
        block_hash = self.generatetoblsctaddress(node, 1, self.miner_addr)[0]
        block_txs = node.getblock(block_hash)["tx"]
        # The coinbase and the transaction both sends were merged into.
        assert_equal(len(block_txs), 2)
        assert send_txid not in block_txs, "send was not merged"

        unspent = wallet.listblsctunspent(0, 9999999)
        assert_equal(len(unspent), 1)
        change_outid = unspent[0]["outid"]
        change = to_dec(unspent[0]["amount"])
        assert change_outid != funding_outid

        # Disconnecting the block puts the merged transaction back in the
        # mempool, so the change row is no longer confirmed when the send is
        # forgotten.
        node.invalidateblock(block_hash)
        assert_equal(node.getrawmempool(), [block_txs[1]])
        unspent = wallet.listblsctunspent(0, 9999999)
        assert_equal([(u["outid"], u["confirmations"]) for u in unspent], [(change_outid, 0)])

        wallet.removeprunedfunds(send_txid)
        # The funding coin stays spent by the merged transaction.
        unspent = wallet.listblsctunspent(0, 9999999)
        self.log.info(f"[merged unconfirmed zapped] listblsctunspent="
                      f"{[(u['outid'], u['amount']) for u in unspent]}")
        assert funding_outid not in [u["outid"] for u in unspent]

        # Reconnecting the block confirms the merged transaction again, and
        # the block scan restores the change row the zap erased.
        node.reconsiderblock(block_hash)
        assert_equal(node.getbestblockhash(), block_hash)
        self.assert_holds_change(wallet, change_outid, change, "merged unconfirmed reconnected")
        return name, change_outid, change

    def spend_change(self, wallet, outid, change):
        """Send from `wallet`, whose only coin is the change `outid`, and mine
        the send: the change is spent and the new change is the only coin."""
        wallet.sendtoblsctaddress(self.receiver_addr, SEND_AMOUNT)
        self.generate_blsct_blocks(self.miner_addr, 1)
        unspent = wallet.listblsctunspent(0, 9999999)
        assert_equal(len(unspent), 1)
        assert unspent[0]["outid"] != outid
        new_change = to_dec(unspent[0]["amount"])
        assert new_change < change - SEND_AMOUNT
        assert_equal(to_dec(wallet.getbalances()["mine"]["trusted"]), new_change)

    def assert_holds_change(self, wallet, outid, change, scenario):
        """`wallet` holds exactly the confirmed change `outid`."""
        mine = wallet.getbalances()["mine"]
        unspent = wallet.listblsctunspent(0, 9999999)
        self.log.info(f"[{scenario}] getbalances.mine={mine} listblsctunspent="
                      f"{[(u['outid'], u['amount']) for u in unspent]}")
        assert_equal(to_dec(mine["trusted"]), change)
        assert_equal(to_dec(mine["untrusted_pending"]), Decimal("0"))
        assert_equal([(u["outid"], to_dec(u["amount"])) for u in unspent],
                     [(outid, change)])

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

        self.log.info("removeprunedfunds of a send merged into a block transaction")
        merged_name, merged_outid, merged_change = self.merge_send_and_forget()

        self.log.info("removeprunedfunds of a merged send while its block is disconnected")
        reconnected_name, reconnected_outid, reconnected_change = self.merge_disconnect_and_forget()

        self.log.info("Every wallet keeps what it held after a restart")
        self.restart_node(0)
        for name, outid in (control, storage):
            node.loadwallet(name)
            self.assert_holds_only(node.get_wallet_rpc(name), outid, f"{name} restarted")
        merged = ((merged_name, merged_outid, merged_change),
                  (reconnected_name, reconnected_outid, reconnected_change))
        for name, outid, change in merged:
            node.loadwallet(name)
            self.assert_holds_change(node.get_wallet_rpc(name), outid, change, f"{name} restarted")

        self.log.info("A change row kept or restored after the zap can be spent")
        for name, outid, change in merged:
            self.spend_change(node.get_wallet_rpc(name), outid, change)


if __name__ == '__main__':
    BlsctOutputStorageRemovePrunedFundsTest(__file__).main()
