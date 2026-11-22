#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that scanblocks and scantxoutset refuse BLSCT addresses.

A BLSCT output's scriptPubKey is a bare OP_TRUE whatever its recipient, and
the script of a BLSCT address is the same byte, so addr(<blsct address>)
would match every BLSCT output: every block in scanblocks and every coin in
scantxoutset, even for an address that never received anything. Both RPCs
must refuse such a descriptor instead of returning those matches.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_greater_than, assert_raises_rpc_error

REFUSED = "Cannot scan for a BLSCT address"


class ScanBLSCTAddressTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [["-blockfilterindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w", blsct=True)
        w = node.get_wallet_rpc("w")
        mining = w.getnewaddress(label="", address_type="blsct")
        never_used = w.getnewaddress(label="", address_type="blsct")
        self.generatetoblsctaddress(node, 10, mining)
        self.wait_until(lambda: node.getindexinfo()["basic block filter index"]["synced"])

        for address in (mining, never_used):
            desc = node.getdescriptorinfo(f"addr({address})")["descriptor"]
            for scanobject in (desc, {"desc": desc}):
                self.log.info(f"Refuse {scanobject!r}")
                assert_raises_rpc_error(-8, REFUSED, node.scanblocks, "start", [scanobject])
                assert_raises_rpc_error(-8, REFUSED, node.scantxoutset, "start", [scanobject])

        self.log.info("A raw OP_TRUE script is still accepted")
        raw = node.getdescriptorinfo("raw(51)")["descriptor"]
        assert_greater_than(len(node.scanblocks("start", [raw])["relevant_blocks"]), 0)
        assert_greater_than(len(node.scantxoutset("start", [raw])["unspents"]), 0)


if __name__ == "__main__":
    ScanBLSCTAddressTest(__file__).main()
