#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional tests for setblsctseed."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


VALID_SEED_WIF = "cS9umN9w6cDMuRVYdbkfE4c7YUFLJRoXMfhQ569uY4odiQbVN8Rt"


class BLSCTSetSeedTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Create blank BLSCT wallets")
        self.nodes[0].createwallet(wallet_name="seed_a", blsct=True, blank=True)
        self.nodes[0].createwallet(wallet_name="seed_b", blsct=True, blank=True)
        wallet_a = self.nodes[0].get_wallet_rpc("seed_a")
        wallet_b = self.nodes[0].get_wallet_rpc("seed_b")

        self.log.info("Reject invalid seed values")
        assert_raises_rpc_error(-5, "Invalid private key", wallet_a.setblsctseed, "not_wif")
        assert_raises_rpc_error(
            -3,
            "JSON value of type bool is not of expected type string",
            wallet_a.setblsctseed,
            True,
        )

        self.log.info("Set the same seed in two wallets and verify deterministic output")
        wallet_a.setblsctseed(VALID_SEED_WIF)
        wallet_b.setblsctseed(VALID_SEED_WIF)

        seed_a = wallet_a.getblsctseed()
        seed_b = wallet_b.getblsctseed()
        assert_equal(len(seed_a), 64)
        assert_equal(seed_a, seed_b)

        for _ in range(3):
            addr_a = wallet_a.getnewaddress(label="", address_type="blsct")
            addr_b = wallet_b.getnewaddress(label="", address_type="blsct")
            assert_equal(addr_a, addr_b)

        self.log.info("Reject setting a seed that is already present in the wallet")
        assert_raises_rpc_error(-5, "Already have this key", wallet_a.setblsctseed, VALID_SEED_WIF)

        self.log.info("Rotate to a random seed when the argument is omitted")
        old_seed = wallet_b.getblsctseed()
        old_addr = wallet_b.getnewaddress(label="", address_type="blsct")
        wallet_b.setblsctseed()
        new_seed = wallet_b.getblsctseed()
        new_addr = wallet_b.getnewaddress(label="", address_type="blsct")
        assert old_seed != new_seed
        assert old_addr != new_addr

        self.log.info("Reject non-BLSCT wallets")
        self.nodes[0].createwallet(wallet_name="plain_wallet", blank=True)
        plain_wallet = self.nodes[0].get_wallet_rpc("plain_wallet")
        assert_raises_rpc_error(
            -4,
            "Cannot set a BLSCT seed on a non-BLSCT wallet.",
            plain_wallet.setblsctseed,
            VALID_SEED_WIF,
        )

        self.log.info("Reject BLSCT wallets with private keys disabled")
        self.nodes[0].createwallet(
            wallet_name="watch_blsct",
            blsct=True,
            blank=True,
            disable_private_keys=True,
        )
        watch_wallet = self.nodes[0].get_wallet_rpc("watch_blsct")
        assert_raises_rpc_error(
            -4,
            "Cannot set a BLSCT seed to a wallet with private keys disabled",
            watch_wallet.setblsctseed,
            VALID_SEED_WIF,
        )


if __name__ == '__main__':
    BLSCTSetSeedTest().main()
