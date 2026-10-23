#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""An aggregated send whose cover input is double-spent in a block.

Regression for issue #511. An output-storage wallet holding exactly one coin
sends an aggregate T (its own half plus a pooled cover candidate) and a second
send chained on T's change. On another node the cover provider double-spends
its candidate input and mines it. When the block reaches the sender's node,
the wallet must mark T and the chained send conflicted without the user
abandoning anything: the original coin is spendable again, the balance counts
it, and a new send spends it.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Auto-serving is disabled so a candidate lands in node0's pool exactly when
# the test serves one; node1 never aggregates its own sends.
PULL_ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1", "-candidatepullinterval=2", "-servecandidates=0"]
FUNDING_AMOUNT = Decimal("100")
SEND_AMOUNT = Decimal("1")
# In navoshis, well below any coin the producer mined.
DOUBLE_SPEND_AMOUNT = 10000000


class BlsctOutputStorageBlockConflictTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [
            PULL_ARGS,
            PULL_ARGS + ["-aggregatesends=0"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=4):
        remaining = num_blocks
        while remaining > 0:
            to = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to, address)
            remaining -= to

    def serve_candidate(self, requester_node, producer_node, producer_wallet):
        """Answer one of requester's queued pull requests on the producer, wait
        for the requester to pool the candidate, and return its inputs."""
        keys = []

        def got_one():
            keys.extend(producer_node.listpendingcandidaterequests())
            return len(keys) > 0

        self.wait_until(got_one, timeout=120)
        before = requester_node.getaggregationhint()["available"]
        reply = producer_wallet.replycandidate(keys[0])
        self.wait_until(lambda: requester_node.getaggregationhint()["available"] > before, timeout=120)
        return reply["inputs"]

    def send(self, wallet, address):
        """Send SEND_AMOUNT on node0 and return the txid it put in the mempool."""
        n0 = self.nodes[0]
        before = set(n0.getrawmempool())
        wallet.sendtoblsctaddress(address, SEND_AMOUNT)
        added = set(n0.getrawmempool()) - before
        assert_equal(len(added), 1)
        return added.pop()

    def trusted(self, wallet):
        return Decimal(str(wallet.getbalances()["mine"]["trusted"]))

    def coins(self, wallet):
        return sorted((u["outid"], Decimal(str(u["amount"]))) for u in wallet.listblsctunspent(0))

    def run_test(self):
        n0, n1 = self.nodes
        n0.createwallet(wallet_name="funder", blsct=True, storage_output=True)
        n0.createwallet(wallet_name="sender", blsct=True, storage_output=True)
        n1.createwallet(wallet_name="producer", blsct=True, storage_output=True)
        funder = n0.get_wallet_rpc("funder")
        sender = n0.get_wallet_rpc("sender")
        producer = n1.get_wallet_rpc("producer")
        mining_addr = funder.getnewaddress(label="", address_type="blsct")
        producer_addr = producer.getnewaddress(label="", address_type="blsct")
        sender_addr = sender.getnewaddress(label="", address_type="blsct")
        dest = producer.getnewaddress(label="", address_type="blsct")

        self.log.info("Fund the funder and the cover producer past coinbase maturity")
        self.generate_blsct_blocks(n0, mining_addr, 110)
        self.sync_blocks()
        self.generate_blsct_blocks(n1, producer_addr, 110)
        self.sync_blocks()

        self.log.info(f"Fund the sender with exactly one coin of {FUNDING_AMOUNT}")
        funder.sendtoblsctaddress(sender_addr, FUNDING_AMOUNT)
        self.sync_mempools()
        self.generate_blsct_blocks(n1, producer_addr, 1)
        self.sync_blocks()
        coin = self.coins(sender)
        assert_equal([amount for _, amount in coin], [FUNDING_AMOUNT])

        self.log.info("Pool one cover candidate, then cut node0 off from node1")
        candidate_inputs = self.serve_candidate(n0, n1, producer)
        assert_equal(len(candidate_inputs), 1)
        self.disconnect_nodes(0, 1)

        self.log.info("Send an aggregate and a send chained on its change")
        aggregate = self.send(sender, dest)
        aggregate_inputs = {vin["outid"] for vin in n0.getrawtransaction(aggregate, True)["vin"] if "outid" in vin}
        assert_equal(aggregate_inputs, {coin[0][0], candidate_inputs[0]})
        chained = self.send(sender, dest)
        n0.syncwithvalidationinterfacequeue()
        assert self.trusted(sender) < FUNDING_AMOUNT - 2 * SEND_AMOUNT

        self.log.info("The cover provider double-spends its candidate input on node1 and mines it")
        raw = producer.createblsctrawtransaction([{"outid": candidate_inputs[0]}],
                                                 [{"address": producer_addr, "amount": DOUBLE_SPEND_AMOUNT}])
        signed = producer.signblsctrawtransaction(producer.fundblsctrawtransaction(raw))
        double_spend = n1.sendrawtransaction(signed)
        double_spend_inputs = {vin["outid"] for vin in n1.getrawtransaction(double_spend, True)["vin"] if "outid" in vin}
        assert candidate_inputs[0] in double_spend_inputs
        assert coin[0][0] not in double_spend_inputs
        self.generatetoblsctaddress(n1, 1, producer_addr, sync_fun=self.no_op)
        assert double_spend not in n1.getrawmempool()

        self.log.info("Reconnect: the block conflicts the aggregate and the chained send")
        self.connect_nodes(0, 1)
        self.sync_blocks()
        n0.syncwithvalidationinterfacequeue()
        mempool = n0.getrawmempool()
        assert aggregate not in mempool
        assert chained not in mempool
        for txid in (aggregate, chained):
            confirmations = sender.gettransaction(txid)["confirmations"]
            self.log.info(f"{txid}: confirmations={confirmations}")
            assert confirmations < 0

        self.log.info("The original coin is spendable again without abandontransaction")
        assert_equal(self.coins(sender), coin)
        assert_equal(self.trusted(sender), FUNDING_AMOUNT)

        self.log.info("A new send spends it")
        new_txid = self.send(sender, dest)
        new_inputs = {vin["outid"] for vin in n0.getrawtransaction(new_txid, True)["vin"] if "outid" in vin}
        assert coin[0][0] in new_inputs
        self.sync_mempools()
        self.generate_blsct_blocks(n1, producer_addr, 1)
        self.sync_blocks()
        n0.syncwithvalidationinterfacequeue()
        assert new_txid not in n0.getrawmempool()
        balance = self.trusted(sender)
        assert FUNDING_AMOUNT - SEND_AMOUNT - Decimal("1") < balance < FUNDING_AMOUNT - SEND_AMOUNT


if __name__ == "__main__":
    BlsctOutputStorageBlockConflictTest(__file__).main()
