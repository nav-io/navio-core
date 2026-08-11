#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test that UTXO-set RPCs omit amounts on a confidential chain.

On a BLSCT chain an output's value is a Pedersen commitment, so the plain
nValue the coin statistics sum over is not the amount. gettxoutsetinfo and
scantxoutset must therefore leave their amount fields out entirely rather than
report a number that is not the coin supply. Everything else they report is
still meaningful and must survive.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_greater_than_or_equal

AMOUNT_FIELDS = ("total_amount", "total_unspendable_amount", "block_info")


class BLSCTTxoutsetAmountsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [["-coinstatsindex"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_no_amounts(self, stats):
        for field in AMOUNT_FIELDS:
            assert field not in stats, f"{field} must be absent on a confidential chain, got {stats.get(field)!r}"

    def assert_common_fields(self, node, stats, height):
        assert_equal(stats["height"], height)
        assert_equal(stats["bestblock"], node.getbestblockhash())
        assert_greater_than(stats["txouts"], 0)
        assert_greater_than(stats["bogosize"], 0)

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="wallet", blsct=True)
        wallet = node.get_wallet_rpc("wallet")

        address = wallet.getnewaddress(label="", address_type="blsct")
        blocks = 10
        self.generatetoblsctaddress(node, blocks, address)
        self.wait_until(lambda: node.getindexinfo()["coinstatsindex"]["synced"])

        self.log.info("gettxoutsetinfo omits amounts without the coinstats index")
        stats = node.gettxoutsetinfo("hash_serialized_3")
        self.assert_no_amounts(stats)
        self.assert_common_fields(node, stats, blocks)
        assert_equal(len(stats["hash_serialized_3"]), 64)
        # These two are only reported when the index is not consulted, which is
        # the case for the hash_serialized_3 hash type. disk_size is a leveldb
        # estimate that is legitimately 0 for a chain this short, so only assert
        # it is reported at all.
        assert_greater_than(stats["transactions"], 0)
        assert_greater_than_or_equal(stats["disk_size"], 0)

        self.log.info("gettxoutsetinfo omits amounts and block_info with the coinstats index")
        indexed = node.gettxoutsetinfo("muhash")
        self.assert_no_amounts(indexed)
        self.assert_common_fields(node, indexed, blocks)
        assert_equal(len(indexed["muhash"]), 64)
        assert_equal(indexed["txouts"], stats["txouts"])
        assert_equal(indexed["bogosize"], stats["bogosize"])

        self.log.info("gettxoutsetinfo omits amounts for a historical height too")
        historical = node.gettxoutsetinfo("muhash", blocks - 1)
        self.assert_no_amounts(historical)
        assert_equal(historical["height"], blocks - 1)
        assert_equal(historical["bestblock"], node.getblockhash(blocks - 1))

        self.log.info("gettxoutsetinfo omits amounts for the 'none' hash type")
        self.assert_no_amounts(node.gettxoutsetinfo("none"))

        self.log.info("scantxoutset omits total_amount")
        # Confidential outputs pay to a bare OP_TRUE (0x51) script, so a raw
        # descriptor for it matches the coinbase outputs generated above.
        descriptor = node.getdescriptorinfo("raw(51)")["descriptor"]
        scan = node.scantxoutset("start", [descriptor])
        assert_equal(scan["success"], True)
        assert "total_amount" not in scan, f"total_amount must be absent on a confidential chain, got {scan.get('total_amount')!r}"
        assert_equal(scan["height"], blocks)
        assert_equal(scan["bestblock"], node.getbestblockhash())
        assert_greater_than(len(scan["unspents"]), 0)
        for unspent in scan["unspents"]:
            assert_greater_than(unspent["height"], 0)


if __name__ == "__main__":
    BLSCTTxoutsetAmountsTest(__file__).main()
