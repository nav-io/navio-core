#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mempool acceptance requires every spendable output to be new.

An output is identified by the hash of its content, and a block may not
create the same spendable output twice. The mempool therefore rejects a
transaction that repeats one of its own spendable outputs, or one that
another mempool transaction already creates (unless it replaces that
transaction), or that is still unspent in the chain. Unspendable outputs may
repeat.
"""

from copy import deepcopy

from test_framework.messages import (
    COIN,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

AMOUNT = 1 * COIN


class MempoolDuplicateOutputTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def check(self, tx, allowed, reason=None):
        res = self.node.testmempoolaccept([tx.serialize().hex()])[0]
        assert_equal(res["allowed"], allowed)
        if reason is not None:
            assert_equal(res["reject-reason"], reason)

    def make_tx(self, outputs):
        """Spend a fresh wallet UTXO into `outputs` plus change."""
        tx = self.wallet.create_self_transfer_multi(num_outputs=1)["tx"]
        change = tx.vout[0]
        change.nValue -= sum(o.nValue for o in outputs)
        tx.vout = [deepcopy(o) for o in outputs] + [change]
        tx.rehash()
        return tx

    def run_test(self):
        self.node = self.nodes[0]
        self.wallet = MiniWallet(self.node)
        self.generate(self.wallet, 10)
        self.generate(self.node, 100)
        self.wallet.rescan_utxos()

        shared = CTxOut(AMOUNT, bytearray(self.wallet.get_scriptPubKey()))
        shared.predicate = b"\x01" * 8

        self.log.info("A transaction creating a new output is accepted")
        tx_a = self.make_tx([shared])
        self.check(tx_a, True)
        self.wallet.sendrawtransaction(from_node=self.node, tx_hex=tx_a.serialize().hex())

        self.log.info("Another transaction creating the same output is rejected")
        tx_b = self.make_tx([shared])
        self.check(tx_b, False, "txn-duplicate-output")

        self.log.info("A transaction repeating one of its own outputs is rejected")
        other = deepcopy(shared)
        other.predicate = b"\x02" * 8
        self.check(self.make_tx([other, other]), False, "txn-duplicate-output")

        self.log.info("A package creating the same output twice is rejected")
        third = deepcopy(shared)
        third.predicate = b"\x03" * 8
        res = self.node.testmempoolaccept([self.make_tx([third]).serialize().hex(), self.make_tx([third]).serialize().hex()])
        assert_equal(res[0]["package-error"], "package-duplicate-output")

        self.log.info("A replacement may recreate an output of the transaction it replaces")
        tx_a_replacement = deepcopy(tx_a)
        tx_a_replacement.vout[-1].nValue -= 10000
        tx_a_replacement.rehash()
        self.check(tx_a_replacement, True)
        self.node.sendrawtransaction(tx_a_replacement.serialize().hex())
        assert tx_a.hash not in self.node.getrawmempool()
        assert tx_a_replacement.hash in self.node.getrawmempool()

        self.log.info("Unspendable outputs may repeat across transactions")
        burn = CTxOut(0, CScript([OP_RETURN, b"\xaa" * 4]))
        for _ in range(2):
            tx = self.make_tx([burn])
            self.check(tx, True)
            self.node.sendrawtransaction(tx.serialize().hex())

        self.log.info("An output that is unspent in the chain cannot be recreated")
        self.generate(self.node, 1)
        assert_equal(self.node.getrawmempool(), [])
        self.check(self.make_tx([shared]), False, "txn-duplicate-output")


if __name__ == "__main__":
    MempoolDuplicateOutputTest(__file__).main()
