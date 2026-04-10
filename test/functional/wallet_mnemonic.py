#!/usr/bin/env python3
# Copyright (c) 2024 The Navio developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP-39 mnemonic wallet support."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletMnemonicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Test dumpmnemonic on a new BLSCT wallet")
        node.createwallet(wallet_name="test_blsct", blsct=True)
        w = node.get_wallet_rpc("test_blsct")
        mnemonic = w.dumpmnemonic()
        words = mnemonic.split()
        assert_equal(len(words), 24)

        self.log.info("Test restore from mnemonic produces same seed")
        seed_a = w.getblsctseed()
        node.createwallet(wallet_name="test_restored", blsct=True, mnemonic=mnemonic)
        w2 = node.get_wallet_rpc("test_restored")
        seed_b = w2.getblsctseed()
        assert_equal(seed_a, seed_b)

        self.log.info("Test dumpmnemonic on non-BLSCT wallet errors")
        node.createwallet(wallet_name="test_descriptor")
        w3 = node.get_wallet_rpc("test_descriptor")
        assert_raises_rpc_error(-4, None, w3.dumpmnemonic)

        self.log.info("Test createwallet with blsct=true returns mnemonic in response")
        result = node.createwallet(wallet_name="test_new_blsct", blsct=True)
        assert "mnemonic" in result
        words = result["mnemonic"].split()
        assert_equal(len(words), 24)

        self.log.info("Test createwallet with mnemonic param restores correctly")
        w_new = node.get_wallet_rpc("test_new_blsct")
        seed_new = w_new.getblsctseed()
        mnemonic_new = result["mnemonic"]
        node.createwallet(wallet_name="test_from_mnemonic", blsct=True, mnemonic=mnemonic_new)
        w_from = node.get_wallet_rpc("test_from_mnemonic")
        seed_from = w_from.getblsctseed()
        assert_equal(seed_new, seed_from)

        self.log.info("Test createwallet with both mnemonic and seed errors")
        assert_raises_rpc_error(-8, "Cannot specify both",
            node.createwallet, wallet_name="test_both",
            blsct=True, seed="00" * 32, mnemonic="abandon " * 23 + "art")

        self.log.info("Test createwallet with invalid mnemonic errors")
        assert_raises_rpc_error(-8, "Invalid mnemonic",
            node.createwallet, wallet_name="test_invalid",
            blsct=True, mnemonic="invalid words here that are not real")


if __name__ == '__main__':
    WalletMnemonicTest().main()
