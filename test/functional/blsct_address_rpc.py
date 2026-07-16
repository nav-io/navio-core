#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that address-generating RPCs are consistently BLSCT-aware.

On a BLSCT wallet, `getnewaddress` and `getrawchangeaddress` must both
return confidential (`rnv1...`) addresses, and requesting an explicit
transparent `address_type` must be rejected rather than silently handing
back an address that breaks the wallet's confidentiality guarantees.

Transparent wallets must be unaffected: `getrawchangeaddress` should keep
returning addresses of the wallet's configured change/address type.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BlsctAddressRpcTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create a BLSCT wallet and a transparent (bech32) wallet")
        node.createwallet(wallet_name="blsct_wallet", blsct=True)
        node.createwallet(wallet_name="plain_wallet", blsct=False)
        blsct_wallet = node.get_wallet_rpc("blsct_wallet")
        plain_wallet = node.get_wallet_rpc("plain_wallet")

        self.log.info("getnewaddress on a BLSCT wallet returns an rnv1... address by default")
        addr = blsct_wallet.getnewaddress()
        assert addr.startswith("rnv1")
        assert_equal(blsct_wallet.getaddressinfo(addr)["isblsct"], True)

        self.log.info("getnewaddress with address_type=blsct explicitly also works")
        addr = blsct_wallet.getnewaddress(label="", address_type="blsct")
        assert addr.startswith("rnv1")
        assert_equal(blsct_wallet.getaddressinfo(addr)["isblsct"], True)

        self.log.info("getnewaddress rejects an explicit transparent address_type on a BLSCT wallet")
        for bad_type in ("bech32", "legacy", "p2sh-segwit", "bech32m"):
            assert_raises_rpc_error(
                -8,
                "This is a BLSCT wallet; addresses must be of type \"blsct\"",
                blsct_wallet.getnewaddress,
                "",
                bad_type,
            )

        self.log.info("getrawchangeaddress on a BLSCT wallet returns an rnv1... change address")
        change_addr = blsct_wallet.getrawchangeaddress()
        assert change_addr.startswith("rnv1")
        assert_equal(blsct_wallet.getaddressinfo(change_addr)["isblsct"], True)

        self.log.info("getrawchangeaddress with address_type=blsct explicitly also works")
        change_addr2 = blsct_wallet.getrawchangeaddress(address_type="blsct")
        assert change_addr2.startswith("rnv1")

        self.log.info("getrawchangeaddress rejects an explicit transparent address_type on a BLSCT wallet")
        for bad_type in ("bech32", "legacy", "p2sh-segwit", "bech32m"):
            assert_raises_rpc_error(
                -8,
                "This is a BLSCT wallet; addresses must be of type \"blsct\"",
                blsct_wallet.getrawchangeaddress,
                bad_type,
            )

        self.log.info("BLSCT change addresses are drawn from a distinct pool than receive addresses")
        receive_addr = blsct_wallet.getnewaddress()
        assert receive_addr != change_addr
        assert receive_addr != change_addr2
        # NOTE: change_addr == change_addr2 here. This mirrors a pre-existing
        # quirk of blsct::KeyMan's negative "special account" handling
        # (CHANGE_ACCOUNT/STAKING_ACCOUNT always resolve to sub-address index 0,
        # see blsct::KeyMan::GetSubAddressFromPool in src/blsct/wallet/keyman.cpp)
        # that also affects real BLSCT sends via blsct::TxFactory, which calls
        # the identical GetNewDestination(blsct::CHANGE_ACCOUNT) path. It is out
        # of scope for this RPC-consistency fix to change keyman derivation
        # behavior, so this test documents current behavior rather than
        # asserting index uniqueness across repeated change-address calls.
        assert_equal(change_addr, change_addr2)

        self.log.info("Transparent wallets are unaffected: getnewaddress/getrawchangeaddress keep working")
        plain_addr = plain_wallet.getnewaddress()
        assert not plain_addr.startswith("rnv1")
        assert_equal(plain_wallet.getaddressinfo(plain_addr).get("isblsct"), None)

        plain_change_addr = plain_wallet.getrawchangeaddress()
        assert not plain_change_addr.startswith("rnv1")

        # Default address/change type is bech32 (see DEFAULT_ADDRESS_TYPE);
        # explicit non-BLSCT address_type requests keep working unaffected.
        legacy_change = plain_wallet.getrawchangeaddress(address_type="legacy")
        info = plain_wallet.getaddressinfo(legacy_change)
        assert not info.get("iswitness", False)

        bech32_change = plain_wallet.getrawchangeaddress(address_type="bech32")
        info = plain_wallet.getaddressinfo(bech32_change)
        assert info.get("iswitness", False)


if __name__ == "__main__":
    BlsctAddressRpcTest(__file__).main()
