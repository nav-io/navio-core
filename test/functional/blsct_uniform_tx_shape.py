#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Output padding (-blsctpadoutputs).

An exact-amount send, a sweep or a subtract-fee send leaves no change. When
that zero change was dropped these sends had one output fewer than every other
send, which set them apart in the mempool. With padding (the default) the zero
change is emitted as an ordinary range-proofed output, so every plain send has
recipient + change. -blsctpadoutputs=0 restores the old shape.

Also checks that the zero-value change does not disturb the wallet: balances
stay exact, and a later ordinary send still works.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def non_fee_outputs(decoded):
    # The fee output is the OP_RETURN burn (scriptPubKey 0x6a); every other
    # BLSCT output is a range-proofed OP_TRUE output.
    return [o for o in decoded["vout"] if o["scriptPubKey"]["hex"] != "6a"]


class BlsctUniformTxShapeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mempool_tx(self, node):
        mempool = node.getrawmempool()
        assert_equal(len(mempool), 1)
        return node.getrawtransaction(mempool[0], True)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="miner", blsct=True)
        node.createwallet(wallet_name="alice", blsct=True)
        node.createwallet(wallet_name="bob", blsct=True)
        miner = node.get_wallet_rpc("miner")
        alice = node.get_wallet_rpc("alice")
        bob = node.get_wallet_rpc("bob")

        mining_addr = miner.getnewaddress(label="", address_type="blsct")
        self.generatetoblsctaddress(node, 120, mining_addr)

        alice_addr = alice.getnewaddress(label="", address_type="blsct")
        bob_addr = bob.getnewaddress(label="", address_type="blsct")

        self.log.info("Ordinary send: recipient + change")
        miner.sendtoaddress(alice_addr, Decimal("10"))
        assert_equal(len(non_fee_outputs(self.mempool_tx(node))), 2)
        self.generatetoblsctaddress(node, 1, mining_addr)
        assert_equal(alice.getbalance(), Decimal("10"))

        self.log.info("Sweep (subtract fee, whole balance): padded to recipient + zero change")
        alice.sendtoaddress(bob_addr, Decimal("10"), "", "", True)
        assert_equal(len(non_fee_outputs(self.mempool_tx(node))), 2)
        self.generatetoblsctaddress(node, 1, mining_addr)
        # The zero change is Alice's but worth nothing: her balance is exactly 0.
        assert_equal(alice.getbalance(), Decimal("0"))
        received = bob.getbalance()
        assert Decimal("10") > received > Decimal("9.9")
        alice.listtransactions()  # must not choke on the zero-value output

        self.log.info("Exact-amount send: padded to recipient + zero change")
        # Fund Alice again, then send back exactly what she can afford so no
        # change remains: the amount is her balance minus the fee of a
        # 1-in/2-out send, which the sweep above had as well.
        miner.sendtoaddress(alice_addr, Decimal("5"))
        self.generatetoblsctaddress(node, 1, mining_addr)
        sweep_fee = Decimal("10") - received
        self.log.info(f"fee of a padded 1-in/2-out send: {sweep_fee}")
        alice.sendtoaddress(bob_addr, Decimal("5") - sweep_fee)
        tx = self.mempool_tx(node)
        assert_equal(len(non_fee_outputs(tx)), 2)
        # Only the funded coin was spent; the earlier zero-value change is
        # never pulled in as an input.
        assert_equal(len(tx["vin"]), 1)
        self.generatetoblsctaddress(node, 1, mining_addr)
        assert_equal(alice.getbalance(), Decimal("0"))

        self.log.info("-blsctpadoutputs=0: a sweep has a single non-fee output")
        self.restart_node(0, extra_args=["-blsctpadoutputs=0"])
        node.loadwallet("bob")
        bob = node.get_wallet_rpc("bob")
        bal = bob.getbalance()
        bob.sendtoaddress(bob.getnewaddress(label="", address_type="blsct"), bal, "", "", True)
        assert_equal(len(non_fee_outputs(self.mempool_tx(node))), 1)


if __name__ == '__main__':
    BlsctUniformTxShapeTest(__file__).main()
