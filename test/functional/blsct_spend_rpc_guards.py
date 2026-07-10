#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional tests for the BLSCT guards on transparent-only spend RPCs.

navio's proper wallet format is BLSCT (confidential). The transparent-only
spend RPCs in wallet/rpc/spend.cpp must never silently be driven against a
BLSCT wallet (they would build a transparent transaction and/or leave
confidential balance behind), nor against a BLSCT destination address (they
would build a broken, unspendable transparent output). This test asserts
that each guarded RPC fails fast with an actionable error pointing at the
correct blsct RPC, instead of silently doing the wrong thing.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error


class BLSCTSpendRPCGuardsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create a blank BLSCT (confidential) wallet")
        node.createwallet(wallet_name="blsct_wallet", blsct=True, blank=True)
        blsct_wallet = node.get_wallet_rpc("blsct_wallet")
        blsct_wallet.setblsctseed()
        blsct_addr = blsct_wallet.getnewaddress(label="", address_type="blsct")

        self.log.info("Create a transparent wallet")
        node.createwallet(wallet_name="transparent_wallet")
        transparent_wallet = node.get_wallet_rpc("transparent_wallet")
        transparent_addr = transparent_wallet.getnewaddress()

        dummy_txid = "00" * 32

        self.log.info("sendmany is rejected on a BLSCT wallet")
        assert_raises_rpc_error(
            -4, "sendtoblsctaddress",
            blsct_wallet.sendmany, "", {transparent_addr: 1},
        )

        self.log.info("send is rejected on a BLSCT wallet")
        assert_raises_rpc_error(
            -4, "sendtoblsctaddress",
            blsct_wallet.send, {transparent_addr: 1},
        )

        self.log.info("sendall is rejected on a BLSCT wallet")
        assert_raises_rpc_error(
            -4, "sendtoblsctaddress",
            blsct_wallet.sendall, [transparent_addr],
        )

        self.log.info("fundrawtransaction is rejected on a BLSCT wallet")
        assert_raises_rpc_error(
            -4, "fundblsctrawtransaction",
            blsct_wallet.fundrawtransaction, "00",
        )

        self.log.info("signrawtransactionwithwallet is rejected on a BLSCT wallet")
        assert_raises_rpc_error(
            -4, "signblsctrawtransaction",
            blsct_wallet.signrawtransactionwithwallet, "00",
        )

        self.log.info("bumpfee is rejected on a BLSCT wallet")
        assert_raises_rpc_error(
            -4, "BLSCT",
            blsct_wallet.bumpfee, dummy_txid,
        )

        self.log.info("psbtbumpfee is rejected on a BLSCT wallet")
        assert_raises_rpc_error(
            -4, "BLSCT",
            blsct_wallet.psbtbumpfee, dummy_txid,
        )

        self.log.info("walletprocesspsbt is rejected on a BLSCT wallet")
        assert_raises_rpc_error(
            -4, "blsct",
            blsct_wallet.walletprocesspsbt, "cHNidP8AAAA=",
        )

        self.log.info("walletcreatefundedpsbt is rejected on a BLSCT wallet")
        assert_raises_rpc_error(
            -4, "blsct",
            blsct_wallet.walletcreatefundedpsbt, [], [{"data": "00"}],
        )

        self.log.info("sendmany rejects a BLSCT destination even from a transparent wallet")
        assert_raises_rpc_error(
            -8, "sendtoblsctaddress",
            transparent_wallet.sendmany, "", {blsct_addr: 1},
        )

        self.log.info("send rejects a BLSCT destination even from a transparent wallet")
        assert_raises_rpc_error(
            -8, "sendtoblsctaddress",
            transparent_wallet.send, {blsct_addr: 1},
        )


if __name__ == '__main__':
    BLSCTSpendRPCGuardsTest(__file__).main()
