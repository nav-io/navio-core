#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""A wallet imported from a seed must report the SAME transaction history as the
wallet that originally created the transactions.

Two regressions this reproduces (both output-storage / mapOutputs only):

A. Dates. Output-storage history entries reported `time`/`timereceived` from
   CWalletOutput::nTimeReceived, which during a rescan is the wall-clock time of
   the import, not the block time. The created wallet (CWalletTx, ComputeTimeSmart)
   shows real block times; the imported one showed everything "just now".

B. Send legs / change. The output-only listing emits credit rows only
   (receive/stake/generate); the `send` (debit) leg is produced solely from the
   CWalletTx path. An imported wallet has no CWalletTx for sends it did not
   create, so its sends vanished and the change output leaked as a `receive`.

The created and imported wallets share one seed, so their confirmed histories
must be identical when projected onto (category, amount, blockheight) and the
per-entry `time` must equal the block time.
"""

from collections import Counter
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


# Deterministic BLSCT seed (same WIF used by blsct_setblsctseed.py): 0x01 * 32.
SEED_WIF = "cMceqPhHedrhbcR9eXgzmfWy7kRqLyAxMYwFT6ABDWsiwUp9Nsq9"


class BlsctImportedWalletHistoryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=2):
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to_generate, address)
            remaining -= to_generate

    def project(self, wallet):
        """Confirmed history as a multiset of (category, amount, blockheight),
        plus a {(category, amount, blockheight): time} map for date checks."""
        entries = wallet.listtransactions("*", 100000, 0, True)
        rows = Counter()
        times = {}
        for e in entries:
            if e.get("confirmations", 0) <= 0:
                continue
            key = (e["category"], Decimal(str(e["amount"])), e.get("blockheight"))
            rows[key] += 1
            times[key] = e.get("time")
        return rows, times

    def block_times(self):
        n = self.nodes[0]
        return {h: n.getblockheader(n.getblockhash(h))["time"]
                for h in range(n.getblockcount() + 1)}

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create the origin wallet from a known seed")
        node.createwallet(wallet_name="created", blsct=True, blank=True, storage_output=True)
        created = node.get_wallet_rpc("created")
        created.setblsctseed(SEED_WIF)
        mining_addr = created.getnewaddress(label="", address_type="blsct")

        # Mature rewards and build a buffer for staking.
        self.generate_blsct_blocks(node, mining_addr, 210)

        self.log.info("Produce sends: a stakelock and a plain self-send")
        created.stakelock(Decimal("100"))
        self.generate_blsct_blocks(node, mining_addr, 1)
        recv_addr = created.getnewaddress(label="", address_type="blsct")
        created.sendtoblsctaddress(recv_addr, Decimal("5"))
        self.generate_blsct_blocks(node, mining_addr, 2)

        self.log.info("Import the same seed into a fresh wallet and rescan")
        node.createwallet(wallet_name="imported", blsct=True, blank=True, storage_output=True)
        imported = node.get_wallet_rpc("imported")
        imported.setblsctseed(SEED_WIF)
        imported.rescanblockchain()

        created_rows, created_times = self.project(created)
        imported_rows, imported_times = self.project(imported)

        self.log.info("Both wallets must report identical confirmed history")
        if created_rows != imported_rows:
            only_created = created_rows - imported_rows
            only_imported = imported_rows - created_rows
            self.log.error(f"only in created:  {sorted(only_created.elements())}")
            self.log.error(f"only in imported: {sorted(only_imported.elements())}")
        assert_equal(created_rows, imported_rows)

        self.log.info("Bug A: imported entry times must be block times, not rescan time")
        block_time = self.block_times()
        for key, t in imported_times.items():
            height = key[2]
            if height is None:
                continue
            assert_equal(t, block_time[height])

        self.log.info("No entry may claim watch-only involvement: neither wallet imported a script")
        # The inputs of these sends are coinbase/stake outputs held only in
        # mapOutputs; GetDebit must apply the ismine filter to them, or
        # CachedTxIsFromMe(ISMINE_WATCH_ONLY) is true for every such send.
        flagged = {name: [(e["category"], e["txid"]) for e in wallet.listtransactions("*", 100000, 0, True)
                          if e.get("involvesWatchonly")]
                   for name, wallet in (("created", created), ("imported", imported))}
        assert_equal(flagged, {"created": [], "imported": []})
        # The filter must not hide the sends themselves. stakelock returns an
        # output hash, so find the stakelock tx by its stake entry.
        for wallet in (created, imported):
            rows = wallet.listtransactions("*", 100000, 0, True)
            stake_txid = next(e["txid"] for e in rows if e["category"] == "stake")
            assert any(e["category"] == "send" and e["txid"] == stake_txid for e in rows)
        details = created.gettransaction(stake_txid)["details"]
        assert any(d["category"] == "send" for d in details)
        assert_equal([d for d in details if d.get("involvesWatchonly")], [])


if __name__ == '__main__':
    BlsctImportedWalletHistoryTest(__file__).main()
