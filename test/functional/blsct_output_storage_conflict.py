#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A receive whose funding input is double-spent in a block.

Node1 pays an output-storage wallet and, as a control, a full-transaction
BLSCT wallet on node0, and the output-storage wallet spends its unconfirmed
receive in a send of its own. Node1 then double-spends both payments' inputs
while cut off and mines the double-spends in the second of three blocks,
which node0 connects in one step when it reorgs to them from a shorter
branch. The payments and the send are evicted as conflicts and can never
confirm. The output-storage wallet keeps a received tx only as its outputs,
so it must mark them conflicted itself, with the block that conflicts them:
the receive leaves listtransactions, shows negative confirmations in
listpendingtransactions, counts in no balance and no coin list, and stays
that way across a restart; the send spending it is conflicted too. The
full-transaction wallet drops the conflicted receive. Disconnecting a block
above the conflicting one keeps the conflict; disconnecting the conflicting
block makes the receive and the send unconfirmed again.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

FUNDING_AMOUNT = Decimal("10")
RECEIVE_AMOUNT = Decimal("3")
# In navoshis.
SPEND_AMOUNT = 100000000


class BlsctOutputStorageConflictTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine(self, node, address, num_blocks):
        while num_blocks > 0:
            to = min(4, num_blocks)
            self.generatetoblsctaddress(node, to, address)
            num_blocks -= to

    def send(self, wallet, address):
        """Send RECEIVE_AMOUNT from a node1 wallet and return the txid it put in the mempool."""
        node = self.nodes[1]
        before = set(node.getrawmempool())
        wallet.sendtoblsctaddress(address, RECEIVE_AMOUNT)
        added = set(node.getrawmempool()) - before
        assert_equal(len(added), 1)
        return added.pop()

    def receives(self, wallet, txid, pending=False):
        """The wallet's receive entries for txid (an outid for output-storage entries)."""
        rows = wallet.listpendingtransactions("*", 1000) if pending else wallet.listtransactions("*", 1000)
        return [r for r in rows if r["txid"] == txid and r["category"] == "receive"]

    def assert_not_counted(self, wallet):
        balances = wallet.getbalances()["mine"]
        assert_equal(balances["trusted"], 0)
        assert_equal(balances["untrusted_pending"], 0)
        assert_equal(wallet.listblsctunspent(0), [])

    def assert_conflicted(self, receiver, receive_id, spend_txid, control, control_txid, confirmations):
        self.log.info(f"The output-storage receive and the send spending it are conflicted: {confirmations} confirmations")
        assert_equal(self.receives(receiver, receive_id), [])
        pending = self.receives(receiver, receive_id, pending=True)
        assert_equal(len(pending), 1)
        assert_equal(pending[0]["confirmations"], confirmations)
        assert_equal(pending[0]["trusted"], False)
        assert_equal(receiver.gettransaction(spend_txid)["confirmations"], confirmations)
        self.assert_not_counted(receiver)

        self.log.info("The full-transaction control dropped its receive")
        assert_equal(self.receives(control, control_txid), [])
        assert_equal(self.receives(control, control_txid, pending=True), [])
        self.assert_not_counted(control)

    def run_test(self):
        n0, n1 = self.nodes
        n0.createwallet(wallet_name="receiver", blsct=True, storage_output=True)
        n0.createwallet(wallet_name="control", blsct=True, storage_output=False)
        for name in ("miner", "pays_receiver", "pays_control"):
            n1.createwallet(wallet_name=name, blsct=True, storage_output=False, load_on_startup=True)
        receiver = n0.get_wallet_rpc("receiver")
        control = n0.get_wallet_rpc("control")
        miner = n1.get_wallet_rpc("miner")
        miner_addr = miner.getnewaddress(label="", address_type="blsct")

        self.log.info("Give each payer exactly one coin")
        self.mine(n1, miner_addr, 110)
        for name in ("pays_receiver", "pays_control"):
            payer = n1.get_wallet_rpc(name)
            miner.sendtoblsctaddress(payer.getnewaddress(label="", address_type="blsct"), FUNDING_AMOUNT)
        self.mine(n1, miner_addr, 1)

        self.log.info("Pay both node0 wallets; the payments reach node0's mempool")
        receive_txid = self.send(n1.get_wallet_rpc("pays_receiver"), receiver.getnewaddress(label="", address_type="blsct"))
        control_txid = self.send(n1.get_wallet_rpc("pays_control"), control.getnewaddress(label="", address_type="blsct"))
        self.sync_mempools()
        n0.syncwithvalidationinterfacequeue()
        rows = [r for r in receiver.listtransactions() if r["category"] == "receive"]
        assert_equal(len(rows), 1)
        receive_id = rows[0]["txid"]
        assert_equal(rows[0]["confirmations"], 0)
        assert_equal(len(self.receives(control, control_txid)), 1)
        assert_equal(receiver.getbalances()["mine"]["untrusted_pending"], RECEIVE_AMOUNT)
        assert_equal(control.getbalances()["mine"]["untrusted_pending"], RECEIVE_AMOUNT)

        self.log.info("The output-storage wallet spends its unconfirmed receive")
        self.disconnect_nodes(0, 1)
        raw = receiver.createblsctrawtransaction([{"outid": rows[0]["outid"]}], [{"address": miner_addr, "amount": SPEND_AMOUNT}])
        before = set(n0.getrawmempool())
        n0.sendrawtransaction(receiver.signblsctrawtransaction(receiver.fundblsctrawtransaction(raw)))
        added = set(n0.getrawmempool()) - before
        assert_equal(len(added), 1)
        spend_txid = added.pop()
        n0.syncwithvalidationinterfacequeue()
        assert_equal(receiver.gettransaction(spend_txid)["confirmations"], 0)

        self.log.info("Node1 drops its mempool and mines two empty blocks, then a longer branch double-spending both payments")
        self.restart_node(1, extra_args=["-persistmempool=0", "-walletbroadcast=0"])
        assert_equal(n1.getrawmempool(), [])
        short_branch = self.generatetoblsctaddress(n1, 2, miner_addr, sync_fun=self.no_op)
        short_blocks = [n1.getblock(block_hash, 0) for block_hash in short_branch]
        n1.invalidateblock(short_branch[0])
        long_branch = self.generatetoblsctaddress(n1, 1, miner_addr, sync_fun=self.no_op)
        for name, txid in (("pays_receiver", receive_txid), ("pays_control", control_txid)):
            payer = n1.get_wallet_rpc(name)
            payer.abandontransaction(txid)
            # With -walletbroadcast=0 the send stays out of the mempool; submit it by hand.
            payer.sendtoblsctaddress(payer.getnewaddress(label="", address_type="blsct"), RECEIVE_AMOUNT)
            double_spend = [r["txid"] for r in payer.listtransactions() if r["category"] == "send" and not r["abandoned"]]
            assert_equal(len(double_spend), 1)
            n1.sendrawtransaction(payer.gettransaction(double_spend[0])["hex"])
        long_branch += self.generatetoblsctaddress(n1, 2, miner_addr, sync_fun=self.no_op)
        conflicting_block = long_branch[1]
        double_spends = n1.getblock(conflicting_block)["tx"][1:]
        assert_equal(n1.getrawmempool(), [])

        self.log.info("Node0 takes the short branch, then reorgs to the long one")
        for block in short_blocks:
            n0.submitblock(block)
        assert_equal(n0.getbestblockhash(), short_branch[-1])
        n0.syncwithvalidationinterfacequeue()
        assert_equal(len(n0.getrawmempool()), 3)
        # Its first two blocks bring no more work than the short branch, so
        # node0 connects all three in one step, reporting the evictions of
        # the second before the first block.
        for block_hash in long_branch:
            n0.submitblock(n1.getblock(block_hash, 0))
        assert_equal(n0.getbestblockhash(), long_branch[-1])
        n0.syncwithvalidationinterfacequeue()
        assert_equal(n0.getrawmempool(), [])
        # Conflicted by the block one below the tip.
        self.assert_conflicted(receiver, receive_id, spend_txid, control, control_txid, -2)

        self.log.info("The conflicted state survives a restart")
        self.restart_node(0)
        n0.loadwallet("receiver")
        n0.loadwallet("control")
        receiver = n0.get_wallet_rpc("receiver")
        control = n0.get_wallet_rpc("control")
        # Conflicted by the block one below the tip.
        self.assert_conflicted(receiver, receive_id, spend_txid, control, control_txid, -2)

        self.log.info("Disconnecting the block above the conflicting one keeps the conflict")
        # Rule out the short branch, so that node0 stays on the long one.
        n0.invalidateblock(short_branch[0])
        n0.invalidateblock(long_branch[2])
        assert_equal(n0.getbestblockhash(), conflicting_block)
        n0.syncwithvalidationinterfacequeue()
        self.assert_conflicted(receiver, receive_id, spend_txid, control, control_txid, -1)

        self.log.info("Disconnecting the conflicting block makes the receive and the send unconfirmed again")
        n0.invalidateblock(conflicting_block)
        assert_equal(n0.getbestblockhash(), long_branch[0])
        n0.syncwithvalidationinterfacequeue()
        # The double-spends return to node0's mempool; the payment and the
        # send do not, as nothing resubmits them.
        assert_equal(sorted(n0.getrawmempool()), sorted(double_spends))

        # Give node0 a block at the conflicting block's height that leaves
        # the double-spends out: node1 drops them by restarting without its
        # mempool, then mines it. Node0 keeps them in its mempool.
        n1.invalidateblock(conflicting_block)
        self.restart_node(1, extra_args=["-persistmempool=0", "-walletbroadcast=0"])
        assert_equal(n1.getrawmempool(), [])
        replacement = self.generatetoblsctaddress(n1, 1, miner_addr, sync_fun=self.no_op)[0]
        assert_equal(n1.getblock(replacement)["nTx"], 1)
        n0.submitblock(n1.getblock(replacement, 0))
        assert_equal(n0.getbestblockhash(), replacement)
        n0.syncwithvalidationinterfacequeue()
        assert_equal(sorted(n0.getrawmempool()), sorted(double_spends))

        rows = self.receives(receiver, receive_id)
        assert_equal(len(rows), 1)
        assert_equal(rows[0]["confirmations"], 0)
        assert_equal(receiver.gettransaction(spend_txid)["confirmations"], 0)
        # Neither is in the mempool, so the receive is still not counted.
        self.assert_not_counted(receiver)

if __name__ == "__main__":
    BlsctOutputStorageConflictTest(__file__).main()
