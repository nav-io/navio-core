#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""getbalances must report BLSCT watch-only balances.

A BLSCT wallet has no legacy ScriptPubKeyMan, so the scripts it watches through
`importblsctscript` (the HTLC / audit path) live in blsct::KeyMan instead. The
`watchonly` object of getbalances has to appear for those wallets too, and has
to carry the BLSCT watch-only amounts - otherwise it contradicts
`getbalance include_watchonly=true`, which counts them.
"""

import hashlib
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import COIN
from test_framework.util import assert_equal

HTLC_AMOUNT_SATS = 1 * COIN
BLINDING_KEY = "5e" * 32


class BlsctWatchonlyBalancesTest(BitcoinTestFramework):
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

    def assert_watchonly_consistent(self, wallet, expected_trusted):
        """The watchonly section must exist and must account for exactly the
        difference `getbalance include_watchonly=true` reports."""
        balances = wallet.getbalances()
        assert "watchonly" in balances, (
            "getbalances must emit a watchonly object for a wallet holding "
            "BLSCT watch-only scripts")
        watchonly = balances["watchonly"]
        trusted = Decimal(str(watchonly["trusted"]))
        assert_equal(trusted, expected_trusted)
        assert_equal(Decimal(str(watchonly["untrusted_pending"])), Decimal(0))
        assert_equal(Decimal(str(watchonly["immature"])), Decimal(0))

        signable = Decimal(str(wallet.getbalance()))
        with_watchonly = Decimal(str(wallet.getbalance("*", 0, True)))
        assert_equal(with_watchonly - signable, trusted)

    def run_test(self):
        node = self.nodes[0]

        node.createwallet(wallet_name="miner", blsct=True)
        miner = node.get_wallet_rpc("miner")
        self.miner_addr = miner.getnewaddress(label="", address_type="blsct")
        self.generate_blsct_blocks(self.miner_addr, 101)

        node.createwallet(wallet_name="funder", blsct=True)
        # The watcher stores outputs, so the amount it recovers for a watched
        # script through the registered nonce is retained and reported.
        node.createwallet(wallet_name="watcher", blsct=True, storage_output=True)
        funder = node.get_wallet_rpc("funder")
        watcher = node.get_wallet_rpc("watcher")
        funder_addr = funder.getnewaddress(label="", address_type="blsct")
        watcher_addr = watcher.getnewaddress(label="", address_type="blsct")

        miner.sendtoblsctaddress(funder_addr, 10)
        self.generate_blsct_blocks(self.miner_addr, 1)

        self.log.info("A wallet watching nothing gets no watchonly section")
        assert "watchonly" not in watcher.getbalances()

        self.log.info("An imported script with no funds still gets a zero section")
        raw_import = watcher.importblsctscript({"type": "raw", "script": "51"}, False)
        assert_equal(raw_import["success"], True)
        self.assert_watchonly_consistent(watcher, Decimal(0))

        self.log.info("A funded imported script is reported in the watchonly section")
        descriptor = {
            "type": "atomic_swap",
            "address_a": funder_addr,
            "address_b": watcher_addr,
            "hash": hashlib.sha256(bytes([0x5e] * 32)).hexdigest(),
            "locktime": node.getblockcount() + 50,
            "blinding_key": BLINDING_KEY,
        }
        htlc_import = watcher.importblsctscript(descriptor, False)
        assert_equal(htlc_import["success"], True)
        # Still nothing on chain paying that script.
        self.assert_watchonly_consistent(watcher, Decimal(0))

        # The output is blinded to address_a (the funder), so the watcher can
        # only see it via the script it imported, and can only recover its
        # amount via the nonce importblsctscript registered alongside.
        outputs = [{
            "address": funder_addr,
            "script": htlc_import["script"],
            "amount": HTLC_AMOUNT_SATS,
            "blinding_key": BLINDING_KEY,
        }]
        raw = funder.createblsctrawtransaction([], outputs)
        funded = funder.fundblsctrawtransaction(raw)
        signed = funder.signblsctrawtransaction(funded)
        node.sendrawtransaction(signed)
        self.generate_blsct_blocks(self.miner_addr, 1)

        watched = [u for u in watcher.listblsctunspent()
                   if u.get("scriptPubKey") == htlc_import["script"]]
        assert_equal(len(watched), 1)
        assert_equal(watched[0].get("watchonly"), True)

        self.assert_watchonly_consistent(
            watcher, Decimal(HTLC_AMOUNT_SATS) / Decimal(COIN))


if __name__ == '__main__':
    BlsctWatchonlyBalancesTest(__file__).main()
