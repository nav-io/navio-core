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
balances and coins, with one send leg per aggregated send.

A wallet reimported only after the merged block cannot split the block tx back
into the original sends: it reports one send row for the block tx, paying the
whole chain's amount to others with the chain's total fee, and the creating
wallet's balances and coins (#512).

The miner merges a chain of plain sends (-aggregatesends=0, as in #512) the
same way. A sender that keeps full transactions (storage_output=false) replaces
its sends with the merged block tx when it confirms, so it reports the same
single send row as a wallet reimported after the block, which must match it
whether the reimport keeps full transactions or outputs only. An
output-storage sender keeps one send leg per plain send.
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
# Seed of the plain-chain sender that keeps full transactions (bytes_to_wif of
# 32 bytes of 0x02), so it can be reimported too.
PLAIN_SEED_WIF = "cMec2DGaTXkYJYfi7x3ZGjRXkeqmAvYAoWzMAcWj5fdLaqudWsNi"


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

    def assert_merged_send(self, created, imported, merged_txid, chain_txids):
        """A wallet that only ever saw the merged block tx reports it as one
        send of everything the chain paid to others, with the chain's total
        fee, and holds the creating wallet's balances and coins."""
        entries = [e for e in imported.listtransactions("*", 100000, 0, True) if e["confirmations"] > 0]
        self.log.info(f"imported after: history: {[(e['category'], e['amount'], e.get('fee'), e['txid'][:8]) for e in entries]}")
        sends = [e for e in entries if e["category"] == "send"]
        assert_equal([e["txid"] for e in sends], [merged_txid])
        # Every hop paid SEND_AMOUNT to the producer's address; the
        # intermediate change each hop created and the next spent is internal
        # to the merged tx and must not count as sent or received.
        assert_equal(Decimal(str(sends[0]["amount"])), -len(chain_txids) * SEND_AMOUNT)
        # The cover halves pay no fee, so the merged tx's fee is exactly the
        # sum of the creating wallet's per-send fees.
        created_fees = sum(Decimal(str(e["fee"])) for e in created.listtransactions("*", 100000, 0, True) if e["category"] == "send")
        assert_equal(Decimal(str(sends[0]["fee"])), created_fees)
        assert_equal(Counter(e["category"] for e in entries), Counter({"send": 1, "receive": 1}))
        assert_equal(imported.getbalances()["mine"], created.getbalances()["mine"])
        assert_equal(self.coins(imported), self.coins(created))
        self.assert_balance_matches_coins(imported, "imported after confirmation")

    def import_wallet(self, node, name, seed=SEED_WIF, storage_output=True):
        node.createwallet(wallet_name=name, blsct=True, blank=True, storage_output=storage_output)
        wallet = node.get_wallet_rpc(name)
        wallet.setblsctseed(seed)
        wallet.rescanblockchain()
        return wallet

    def plain_chain(self, wallet, dest):
        """Chain CHAIN_LENGTH plain sends of SEND_AMOUNT off one funding UTXO
        on node1 (-aggregatesends=0) and return their txids and fees."""
        n1 = self.nodes[1]
        txids, fees = [], []
        for _ in range(CHAIN_LENGTH):
            mempool_before = set(n1.getrawmempool())
            wallet.sendtoblsctaddress(dest, SEND_AMOUNT)
            new = set(n1.getrawmempool()) - mempool_before
            assert_equal(len(new), 1)
            txid = new.pop()
            # A plain send spends only the previous hop's change.
            assert_equal(len(n1.getrawtransaction(txid, True)["vin"]), 1)
            fee = Decimal(str(wallet.gettransaction(txid)["fee"]))
            assert Decimal("-1") < fee < 0, fee
            txids.append(txid)
            fees.append(fee)
        return txids, fees

    def mine_merged_chain(self, chain_txids, producer_addr):
        """Mine the chain on node1 and return the txid of the block tx the
        miner merged it into."""
        n1 = self.nodes[1]
        assert_equal(set(n1.getrawmempool()), set(chain_txids))
        self.generate_blsct_blocks(n1, producer_addr, 1)
        self.sync_blocks()
        block_txids = n1.getblock(n1.getbestblockhash())["tx"]
        self.log.info(f"mined block txs: {block_txids}")
        assert_equal(len(block_txids), 2)
        assert not set(chain_txids) & set(block_txids)
        assert_equal(n1.getrawmempool(), [])
        n1.syncwithvalidationinterfacequeue()
        return block_txids[1]

    def assert_replaced_by_merged_send(self, wallet, merged_txid, chain_txids, fees, label="full-tx sender"):
        """A sender that keeps full transactions dropped its sends for the
        merged block tx: one send row under the block txid, paying the whole
        chain's amount to others with the sum of the sends' fees."""
        entries = wallet.listtransactions("*", 100000, 0, True)
        self.log.info(f"{label}: history: {[(e['category'], e['amount'], e.get('fee'), e['confirmations'], e['txid'][:8]) for e in entries]}")
        assert all(e["confirmations"] > 0 for e in entries)
        sent = CHAIN_LENGTH * SEND_AMOUNT
        total_fee = sum(fees)
        sends = [e for e in entries if e["category"] == "send"]
        assert_equal([e["txid"] for e in sends], [merged_txid])
        assert_equal(Decimal(str(sends[0]["amount"])), -sent)
        assert_equal(Decimal(str(sends[0]["fee"])), total_fee)
        assert_equal(Counter(e["category"] for e in entries), Counter({"send": 1, "receive": 1}))
        receives = [e for e in entries if e["category"] == "receive"]
        assert_equal(Decimal(str(receives[0]["amount"])), FUNDING_AMOUNT)

        merged = wallet.gettransaction(merged_txid)
        assert_equal(Decimal(str(merged["amount"])), -sent)
        assert_equal(Decimal(str(merged["fee"])), total_fee)
        assert_equal([(d["category"], Decimal(str(d["amount"]))) for d in merged["details"]], [("send", -sent)])
        for txid in chain_txids:
            assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", wallet.gettransaction, txid)

        balances = wallet.getbalances()["mine"]
        assert_equal(Decimal(str(balances["trusted"])), FUNDING_AMOUNT - sent + total_fee)
        assert_equal(Decimal(str(balances["untrusted_pending"])), 0)
        self.assert_balance_matches_coins(wallet, f"{label} after confirmation")

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
        # each to the merged block tx, as for the creating wallet.
        self.assert_same_wallet_view(walletA, unconfirmed_import, "imported before confirmation")
        self.assert_send_legs(unconfirmed_import, chain_txids)
        self.assert_balance_matches_coins(unconfirmed_import, "imported before confirmation, after mining")

        # A wallet reimported only after the merged block never saw the
        # aggregates, and the block tx keeps no boundaries between them, so it
        # reports the whole chain as one send row under the block tx's txid
        # (#512).
        self.log.info("Reimport the seed after the merged block")
        confirmed_import = self.import_wallet(n0, "imported_after")
        self.assert_merged_send(walletA, confirmed_import, block_txids[1], chain_txids)

        self.log.info("Fund a full-tx sender and an output-storage sender for plain chains on node1")
        n1.createwallet(wallet_name="plain_full", blsct=True, blank=True, storage_output=False)
        n1.createwallet(wallet_name="plain_outputs", blsct=True, storage_output=True)
        plain_full = n1.get_wallet_rpc("plain_full")
        plain_full.setblsctseed(PLAIN_SEED_WIF)
        plain_outputs = n1.get_wallet_rpc("plain_outputs")
        # The restart left the funder unloaded.
        n0.loadwallet("funder")
        funder = n0.get_wallet_rpc("funder")
        for wallet in (plain_full, plain_outputs):
            funder.sendtoblsctaddress(wallet.getnewaddress(label="", address_type="blsct"), FUNDING_AMOUNT)
            self.sync_mempools()
            self.generate_blsct_blocks(n1, producer_addr, 1)
            self.sync_blocks()
            assert_equal(len(wallet.listblsctunspent()), 1)

        self.log.info(f"Chain {CHAIN_LENGTH} plain sends from the full-tx sender and confirm them merged")
        full_txids, full_fees = self.plain_chain(plain_full, dest)
        full_merged = self.mine_merged_chain(full_txids, producer_addr)
        self.assert_replaced_by_merged_send(plain_full, full_merged, full_txids, full_fees)

        # The issue's repro: a reimport after the merged block reports what
        # the full-tx sender reports for the same block tx, in either mode.
        for storage_output in (True, False):
            self.log.info(f"Reimport the full-tx sender's seed after the merged block (storage_output={storage_output})")
            plain_import = self.import_wallet(n1, f"plain_imported_after_{storage_output}", PLAIN_SEED_WIF, storage_output)
            self.assert_merged_send(plain_full, plain_import, full_merged, full_txids)
            assert_equal(self.history(plain_import), self.history(plain_full))
            self.assert_replaced_by_merged_send(plain_import, full_merged, full_txids, full_fees, f"reimport (storage_output={storage_output})")

        self.log.info(f"Chain {CHAIN_LENGTH} plain sends from the output-storage sender and confirm them merged")
        outputs_txids, outputs_fees = self.plain_chain(plain_outputs, dest)
        self.mine_merged_chain(outputs_txids, producer_addr)
        self.assert_send_legs(plain_outputs, outputs_txids)
        fee_by_txid = {e["txid"]: Decimal(str(e["fee"])) for e in plain_outputs.listtransactions("*", 100000, 0, True) if e["category"] == "send"}
        assert_equal(fee_by_txid, dict(zip(outputs_txids, outputs_fees)))
        trusted = self.assert_balance_matches_coins(plain_outputs, "output-storage sender after confirmation")
        assert_equal(trusted, FUNDING_AMOUNT - CHAIN_LENGTH * SEND_AMOUNT + sum(outputs_fees))


if __name__ == "__main__":
    BlsctAggregatedUnconfirmedChainTest(__file__).main()
