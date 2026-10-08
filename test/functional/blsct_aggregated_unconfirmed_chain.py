#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Chained unconfirmed sends that are aggregated with cover candidates.

A wallet funded with exactly one confirmed UTXO issues a chain of
sendtoblsctaddress calls, each spending the previous send's still-unconfirmed
change. Before every send a cover candidate is served into node0's pool, so
every send takes the default aggregated path (-aggregatesends): the broadcast
transaction is the wallet's own half combined with a fee-0 cover half, under a
txid the wallet never built.

After each send the wallet's trusted balance must equal the sum of its
spendable coin set (listblsctunspent), and the next send must find the change.

The record of those sends must survive a restart: after reloading the wallet
the balance still agrees with the coin set and one more aggregated send chains
off the unconfirmed change.

A wallet reimported from the same seed while the chain is still unconfirmed
learns the aggregates only from the mempool sync, so it never marks them as
its own sends: their change stays untrusted and it cannot chain a send until
one confirmation. The miner merges the chain into one block tx; after that
block the reimported wallet must report the creating wallet's history,
balances and coins, with one send leg per aggregated send. Reimporting only
after the merged block is a separate known issue (#512), not covered here.
"""

from collections import Counter
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

# Auto-serving is disabled so a candidate lands in node0's pool exactly when
# the test serves one; node1 never aggregates its own sends.
PULL_ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1", "-candidatepullinterval=2", "-servecandidates=0"]
CHAIN_LENGTH = 6
FUNDING_AMOUNT = Decimal("100")
SEND_AMOUNT = Decimal("1")
# Deterministic BLSCT seed (same WIF used by blsct_setblsctseed.py), so the
# sending wallet can be reimported.
SEED_WIF = "cMceqPhHedrhbcR9eXgzmfWy7kRqLyAxMYwFT6ABDWsiwUp9Nsq9"


class BlsctAggregatedUnconfirmedChainTest(BitcoinTestFramework):
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
        """Answer one of requester's queued pull requests on the producer and
        wait for the requester to pool the candidate."""
        keys = []

        def got_one():
            keys.extend(producer_node.listpendingcandidaterequests())
            return len(keys) > 0

        self.wait_until(got_one, timeout=120)
        before = requester_node.getaggregationhint()["available"]
        producer_wallet.replycandidate(keys[0])
        self.wait_until(lambda: requester_node.getaggregationhint()["available"] > before, timeout=120)

    def assert_balance_matches_coins(self, wallet, label):
        trusted = Decimal(str(wallet.getbalances()["mine"]["trusted"]))
        unspent = [Decimal(str(u["amount"])) for u in wallet.listblsctunspent(0)]
        self.log.info(f"{label}: trusted={trusted} unspent={unspent}")
        assert_equal(trusted, sum(unspent))
        return trusted

    def aggregated_send(self, wallet, dest):
        """Send SEND_AMOUNT and return the broadcast txid, asserting the send
        merged one pooled cover candidate."""
        n0 = self.nodes[0]
        pooled = n0.getaggregationhint()["available"]
        assert pooled > 0
        mempool_before = set(n0.getrawmempool())
        wallet.sendtoblsctaddress(dest, SEND_AMOUNT)
        new = set(n0.getrawmempool()) - mempool_before
        assert_equal(len(new), 1)
        txid = new.pop()
        # The candidate was evicted from the pool and the broadcast tx carries
        # the cover's input next to the own half's.
        assert_equal(n0.getaggregationhint()["available"], pooled - 1)
        assert len(n0.getrawtransaction(txid, True)["vin"]) >= 2
        return txid

    def history(self, wallet):
        """Confirmed history as a multiset of (category, amount, blockheight)."""
        rows = Counter()
        for e in wallet.listtransactions("*", 100000, 0, True):
            if e.get("confirmations", 0) <= 0:
                continue
            rows[(e["category"], Decimal(str(e["amount"])), e.get("blockheight"))] += 1
        return rows

    def coins(self, wallet):
        return sorted((u["outid"], Decimal(str(u["amount"]))) for u in wallet.listblsctunspent(0))

    def assert_same_wallet_view(self, created, imported, label):
        """The imported wallet reports the creating wallet's confirmed history,
        balances and coins."""
        self.log.info(f"{label}: compare history, balances and coins with the creating wallet")
        created_rows, imported_rows = self.history(created), self.history(imported)
        if created_rows != imported_rows:
            self.log.error(f"only in created:  {sorted((created_rows - imported_rows).elements())}")
            self.log.error(f"only in imported: {sorted((imported_rows - created_rows).elements())}")
        assert_equal(created_rows, imported_rows)
        assert_equal(imported.getbalances()["mine"], created.getbalances()["mine"])
        assert_equal(self.coins(imported), self.coins(created))

    def assert_send_legs(self, wallet, chain_txids):
        """Each aggregated send is one send leg of SEND_AMOUNT with the own
        half's fee; the cover halves' inputs and outputs and our change add
        no rows; the only receive is the funding."""
        entries = [e for e in wallet.listtransactions("*", 100000, 0, True) if e["confirmations"] > 0]
        self.log.info(f"history: {[(e['category'], e['amount'], e.get('fee'), e['txid'][:8]) for e in entries]}")
        sends = [e for e in entries if e["category"] == "send"]
        assert_equal(sorted(e["txid"] for e in sends), sorted(chain_txids))
        for e in sends:
            assert_equal(Decimal(str(e["amount"])), -SEND_AMOUNT)
            fee = Decimal(str(e["fee"]))
            assert Decimal("-1") < fee < 0, e
        receives = [e for e in entries if e["category"] == "receive"]
        assert_equal([Decimal(str(e["amount"])) for e in receives], [FUNDING_AMOUNT])
        assert_equal(Counter(e["category"] for e in entries), Counter({"send": len(chain_txids), "receive": 1}))

    def import_wallet(self, node, name):
        node.createwallet(wallet_name=name, blsct=True, blank=True, storage_output=True)
        wallet = node.get_wallet_rpc(name)
        wallet.setblsctseed(SEED_WIF)
        wallet.rescanblockchain()
        return wallet

    def run_test(self):
        n0, n1 = self.nodes
        n0.createwallet(wallet_name="funder", blsct=True, storage_output=True)
        n0.createwallet(wallet_name="walletA", blsct=True, blank=True, storage_output=True)
        n1.createwallet(wallet_name="producer", blsct=True, storage_output=True)
        funder = n0.get_wallet_rpc("funder")
        walletA = n0.get_wallet_rpc("walletA")
        walletA.setblsctseed(SEED_WIF)
        producer = n1.get_wallet_rpc("producer")

        mining_addr = funder.getnewaddress(label="", address_type="blsct")
        producer_addr = producer.getnewaddress(label="", address_type="blsct")
        dest = producer.getnewaddress(label="", address_type="blsct")
        addrA = walletA.getnewaddress(label="", address_type="blsct")

        self.log.info("Fund the funder and the cover producer past coinbase maturity")
        self.generate_blsct_blocks(n0, mining_addr, 110)
        self.sync_blocks()
        self.generate_blsct_blocks(n1, producer_addr, 110)
        self.sync_blocks()

        self.log.info(f"Fund walletA with exactly one UTXO of {FUNDING_AMOUNT}")
        funder.sendtoblsctaddress(addrA, FUNDING_AMOUNT)
        self.sync_mempools()
        self.generate_blsct_blocks(n1, producer_addr, 1)
        self.sync_blocks()
        assert_equal(len(walletA.listblsctunspent()), 1)
        self.assert_balance_matches_coins(walletA, "funded")

        self.log.info(f"Pool {CHAIN_LENGTH} cover candidates, one per chain hop")
        for _ in range(CHAIN_LENGTH):
            self.serve_candidate(n0, n1, producer)
        assert_equal(n0.getaggregationhint()["available"], CHAIN_LENGTH)

        # The sends fire back to back with no wait for the wallet's mempool
        # sync in between: each hop must find the previous hop's change
        # through what the send itself recorded, as a plain send does.
        self.log.info(f"Chain {CHAIN_LENGTH} unconfirmed sends, each aggregated with a cover candidate")
        chain_txids = []
        for i in range(CHAIN_LENGTH):
            chain_txids.append(self.aggregated_send(walletA, dest))
            self.assert_balance_matches_coins(walletA, f"after send {i}")
            assert_equal(len(walletA.listblsctunspent(0)), 1)

        n0.syncwithvalidationinterfacequeue()
        self.assert_balance_matches_coins(walletA, "after mempool sync")

        self.log.info("Restart node0: the recorded sends must survive a wallet reload")
        self.restart_node(0)
        self.connect_nodes(0, 1)
        n0.loadwallet("walletA")
        walletA = n0.get_wallet_rpc("walletA")
        assert set(chain_txids) <= set(n0.getrawmempool())
        self.assert_balance_matches_coins(walletA, "after reload")
        assert_equal(len(walletA.listblsctunspent(0)), 1)

        self.log.info("One more aggregated send chains off the unconfirmed change after the reload")
        # Requests queued before the restart carry node0's old reply key; drop
        # them all (each call claims a bounded batch) so the candidate answers
        # a request from the restarted node.
        while n1.listpendingcandidaterequests():
            pass
        self.serve_candidate(n0, n1, producer)
        chain_txids.append(self.aggregated_send(walletA, dest))
        self.assert_balance_matches_coins(walletA, "after send following reload")
        assert_equal(len(walletA.listblsctunspent(0)), 1)
        n0.syncwithvalidationinterfacequeue()
        self.sync_mempools()

        self.log.info("Reimport the seed while the chain is still unconfirmed")
        unconfirmed_import = self.import_wallet(n0, "imported_unconfirmed")
        balances = unconfirmed_import.getbalances()["mine"]
        self.log.info(f"imported before confirmation: balances={balances} unspent={unconfirmed_import.listblsctunspent(0)}")
        coin_set = sum(Decimal(str(u["amount"])) for u in walletA.listblsctunspent(0))
        # The mempool sync gives the reimported wallet the same coin, but it
        # did not build the aggregates, so the change is untrusted pending
        # rather than trusted, counted exactly once, and not spendable.
        assert_equal(Decimal(str(balances["trusted"])), 0)
        assert_equal(Decimal(str(balances["untrusted_pending"])), coin_set)
        assert_equal(unconfirmed_import.listblsctunspent(0), [])
        assert_raises_rpc_error(-6, "Not enough funds", unconfirmed_import.sendtoblsctaddress, dest, SEND_AMOUNT)

        self.log.info("Confirm the chain")
        self.generate_blsct_blocks(n1, producer_addr, 1)
        self.sync_blocks()
        for txid in chain_txids:
            assert txid not in n0.getrawmempool()
        # The miner merges the whole chain into one block tx under a new txid,
        # next to the coinbase.
        block_txids = n0.getblock(n0.getbestblockhash())["tx"]
        self.log.info(f"mined block txs: {block_txids}")
        assert_equal(len(block_txids), 2)
        assert not set(chain_txids) & set(block_txids)
        n0.syncwithvalidationinterfacequeue()
        balance = self.assert_balance_matches_coins(walletA, "after confirmation")
        sent = len(chain_txids) * SEND_AMOUNT
        assert balance < FUNDING_AMOUNT - sent
        assert balance > FUNDING_AMOUNT - sent - Decimal("1")
        self.assert_send_legs(walletA, chain_txids)

        # The reimported wallet got one wallet tx per aggregate from the
        # mempool scan that ends its rescan, and block connection matched
        # each to the merged block tx, as for the creating wallet. A wallet
        # reimported only after the merged block reports the chain as one
        # wrong send row (#512); that case is deliberately not tested here.
        self.assert_same_wallet_view(walletA, unconfirmed_import, "imported before confirmation")
        self.assert_send_legs(unconfirmed_import, chain_txids)
        self.assert_balance_matches_coins(unconfirmed_import, "imported before confirmation, after mining")


if __name__ == "__main__":
    BlsctAggregatedUnconfirmedChainTest(__file__).main()
