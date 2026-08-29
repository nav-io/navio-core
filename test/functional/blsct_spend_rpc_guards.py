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

# A well-formed regtest BLSCT address whose view and spend keys are both the
# identity (point at infinity). It decodes fine and validateaddress calls it
# valid, but its outputs are anyone-can-spend, so the spend RPCs must reject
# it rather than pay it.
NULL_KEY_ADDRESS = "rnv1cqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwvmtas"

# The same, but with the identity in only one of the two key slots (the other
# holds the BLS12-381 G1 generator). These pin both halves of the null-key
# check: dropping either half of the test lets one of them through.
NULL_VIEW_KEY_ADDRESS = "rnv1cqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp9l36wnnr97hjsnf2cuvf756cr7rdzxyl9m5hyz6zn368ut3htzcd327s0le0gdwl7e67q9dkgkxhvmdqls40d"
NULL_SPEND_KEY_ADDRESS = "rnv1jlca8fe3jltegf54vwxyl2dvplpk3rz0ja6tjpdpfcar79cm43vxc40g8luh5xh0lva0qzkmytrthsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqma0f57ul"
NULL_KEY_ADDRESSES = (NULL_KEY_ADDRESS, NULL_VIEW_KEY_ADDRESS, NULL_SPEND_KEY_ADDRESS)


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

        self.log.info("sendtoblsctaddress rejects a destination that is not a BLSCT address")
        assert_raises_rpc_error(
            -5, "Invalid BLSCT address",
            blsct_wallet.sendtoblsctaddress, transparent_addr, 1,
        )

        self.log.info("sendtoblsctaddress rejects a BLSCT address with identity keys")
        assert_raises_rpc_error(
            -5, "BLSCT address has null keys",
            blsct_wallet.sendtoblsctaddress, NULL_KEY_ADDRESS, 1,
        )

        # generatetoblsctaddress builds the coinbase directly, so an identity
        # key there mines the block reward into an anyone-can-spend output --
        # claimable by whoever sees the block first.
        self.log.info("generatetoblsctaddress rejects BLSCT addresses with identity keys")
        for null_address in NULL_KEY_ADDRESSES:
            assert_raises_rpc_error(
                -5, "address has null keys",
                self.nodes[0].rpc.generatetoblsctaddress, 1, null_address,
            )

        self.log.info("generatetoblsctaddress still rejects a non-BLSCT address")
        assert_raises_rpc_error(
            -5, "Invalid BLSCT address",
            self.nodes[0].rpc.generatetoblsctaddress, 1, transparent_addr,
        )

        # delegatestake/redelegatestake take a reward_address that may
        # legitimately be transparent, so they cannot use the BLSCT helper
        # wholesale -- but a BLSCT one with an identity key would have the
        # delegate pay block rewards into an anyone-can-spend output.
        # delegate_pubkey is validated first, so pass a real G1 point: the
        # BLS12-381 G1 generator, whose compressed encoding is fixed by the
        # curve spec.
        g1_generator = ("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c"
                        "55e83ff97a1aeffb3af00adb22c6bb")
        self.log.info("delegatestake rejects a reward_address with identity keys")
        for null_address in NULL_KEY_ADDRESSES:
            assert_raises_rpc_error(
                -5, "reward_address has null keys",
                blsct_wallet.delegatestake, 1, g1_generator, null_address,
            )


if __name__ == '__main__':
    BLSCTSpendRPCGuardsTest(__file__).main()
