#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""A BLSCT wallet must find its outputs on rescan when -blockfilterindex is on.

ScanForWalletTransactions took the fast block-filter rescan for every wallet
whose IsLegacy() was false. A BLSCT wallet without a LegacyScriptPubKeyMan
(as navio-wallet creates it) qualified, but its outputs are found by view key,
not by a scriptPubKey a BIP158 filter can match: its filter query was empty,
every block was skipped, and the rescan found nothing.
"""

from decimal import Decimal
import re
import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlsctRescanBlockFilterTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [["-blockfilterindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_wallet_tool()

    def wallet_tool_create(self, name, *args):
        node = self.nodes[0]
        cmd = [self.options.naviowallet, f"-datadir={node.datadir_path}", f"-chain={self.chain}", f"-wallet={name}", "-blsct", *args, "create"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert_equal(result.stderr, "")
        assert_equal(result.returncode, 0)
        return result.stdout

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=4):
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to_generate, address)
            remaining -= to_generate

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: all(i["synced"] for i in node.getindexinfo().values()))

        node.createwallet(wallet_name="funder", blsct=True)
        funder = node.get_wallet_rpc("funder")
        mining_addr = funder.getnewaddress(label="", address_type="blsct")

        self.log.info("Mine funds for the sending wallet")
        self.generate_blsct_blocks(node, mining_addr, 210)

        self.log.info("Create a BLSCT wallet with navio-wallet (no legacy ScriptPubKeyMan)")
        stdout = self.wallet_tool_create("origin")
        mnemonic = re.search(r"^Mnemonic: (.+)$", stdout, re.MULTILINE).group(1)
        node.loadwallet("origin")
        origin = node.get_wallet_rpc("origin")
        addr = origin.getnewaddress(label="", address_type="blsct")

        self.log.info("Fund the tool-created wallet")
        funder.sendtoblsctaddress(addr, Decimal("1"))
        self.generate_blsct_blocks(node, mining_addr, 1)
        assert_equal(Decimal(str(origin.getblsctbalance())), Decimal("1"))
        node.unloadwallet("origin")

        self.log.info("Restore the mnemonic into a fresh tool-created wallet; loading it rescans")
        self.wallet_tool_create("restored", f"-mnemonic={mnemonic}")
        with node.assert_debug_log(["[restored] Rescan started from block"], unexpected_msgs=["fast variant using block filters"]):
            node.loadwallet("restored")
        restored = node.get_wallet_rpc("restored")
        assert_equal(Decimal(str(restored.getblsctbalance())), Decimal("1"))
        assert_equal(len(restored.listtransactions()), 1)

        self.log.info("An explicit rescanblockchain also inspects every block")
        with node.assert_debug_log(["slow variant inspecting all blocks"], unexpected_msgs=["fast variant using block filters"]):
            restored.rescanblockchain()
        assert_equal(Decimal(str(restored.getblsctbalance())), Decimal("1"))
        receives = [tx for tx in restored.listtransactions() if tx["category"] == "receive"]
        assert_equal([Decimal(str(tx["amount"])) for tx in receives], [Decimal("1")])

        self.log.info("A wallet restored with createwallet has no legacy ScriptPubKeyMan either")
        node.createwallet(wallet_name="rpc_restored", blsct=True, mnemonic=mnemonic)
        rpc_restored = node.get_wallet_rpc("rpc_restored")
        # The framework runs nodes with -keypool=1, so a legacy ScriptPubKeyMan
        # would hold a transparent key here.
        assert_equal(rpc_restored.getwalletinfo()["keypoolsize"], 0)
        with node.assert_debug_log(["[rpc_restored] Rescan started from block"], unexpected_msgs=["fast variant using block filters"]):
            rpc_restored.rescanblockchain()
        assert_equal(Decimal(str(rpc_restored.getblsctbalance())), Decimal("1"))


if __name__ == "__main__":
    BlsctRescanBlockFilterTest(__file__).main()
