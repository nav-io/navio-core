#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Token balances in output-storage (default) BLSCT wallets.

createwallet defaults storage_output=true for BLSCT wallets, but the rest of
the functional suite creates wallets with storage_output=false, so the default
mode had no token coverage: gettokenbalance took only the GetBlsctBalance half
of the tally, whose dedup rule delegates self-created confirmed transactions
(e.g. our own mint) to the CWalletTx path — self-minted tokens were invisible.

Covers: mint visibility in the minting (storage) wallet, transfer visibility
in a receiving storage wallet, and interleaved NAV/token balance queries on
the same wallet (the available-credit cache used to be keyed by filter only,
so whichever token was asked first poisoned the other's answer).
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlsctTokenOutputStorageTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def gb(self, node, addr, num, batch=4):
        r = num
        while r > 0:
            t = min(batch, r)
            self.generatetoblsctaddress(node, t, addr)
            r -= t

    def run_test(self):
        n0, n1 = self.nodes

        # storage_output=True: the default real users get.
        n0.createwallet(wallet_name="w0", blsct=True, storage_output=True)
        n1.createwallet(wallet_name="w1", blsct=True, storage_output=True)
        w0 = n0.get_wallet_rpc("w0")
        w1 = n1.get_wallet_rpc("w1")
        a0 = w0.getnewaddress(label="", address_type="blsct")
        a1 = w1.getnewaddress(label="", address_type="blsct")

        self.gb(n0, a0, 101)
        self.sync_all()
        nav_before = w0.getbalance()
        assert nav_before > 0

        self.log.info("Self-minted token is visible in a storage wallet")
        token = w0.createtoken({"name": "STOK"}, 1000)
        tid = token["tokenId"]
        self.gb(n0, a0, 1)
        w0.minttoken(tid, a0, 5)
        self.gb(n0, a0, 1)
        self.sync_all()

        self.log.info("NAV and token balances do not poison each other's cache")
        # Order matters for this to be a real regression test: the NAV reading
        # must come BEFORE the wallet's first token-scoped query, because that
        # query is what writes token totals into m_amounts[AVAILABLE_CREDIT]
        # when the cache bypass is missing. Comparing two post-token readings
        # would read the same poisoned slot twice and never fail.
        nav_pre = w0.getbalance()
        assert nav_pre > Decimal(0)
        assert_equal(w0.gettokenbalance(tid), 5)
        assert_equal(w0.getbalance(), nav_pre)
        assert_equal(w0.gettokenbalance(tid), 5)

        self.log.info("Token transfer received by another storage wallet is visible")
        w0.sendtokentoblsctaddress(tid, a1, 2)
        self.gb(n0, a0, 2)
        self.sync_all()
        assert_equal(w1.gettokenbalance(tid), 2)
        assert_equal(w0.gettokenbalance(tid), 3)

        self.log.info("Balances survive a restart (reload from storage)")
        self.restart_node(0)
        self.connect_nodes(0, 1)
        n0.loadwallet("w0")
        w0 = n0.get_wallet_rpc("w0")
        assert_equal(w0.gettokenbalance(tid), 3)


if __name__ == '__main__':
    BlsctTokenOutputStorageTest(__file__).main()
