#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test delegated cold staking: delegatestake RPC, on-chain delegation payload,
liststakedcommitmentsdata scan, fee-split block templates and revocation."""

import os.path
import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

# DataPredicate serialization: <DATA op (0x04)> <compact size> <payload>.
# The payload starts with the delegation magic "NVDG" + version 0x01.
DELEGATION_MAGIC_HEX = "4e56444701"


class NavioBlsctColdStakingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def staker_path(self):
        return os.path.join(self.config["environment"]["BUILDDIR"], "bin",
                            "navio-staker" + self.config["environment"]["EXEEXT"])

    def gen_delegation_key(self):
        """Use navio-staker -gendelegationkey to create an operator key pair."""
        out = subprocess.run([self.staker_path(), "-gendelegationkey"],
                             capture_output=True, text=True, check=True).stdout
        priv = pub = None
        for line in out.splitlines():
            if line.startswith("delegation private key:"):
                priv = line.split(":")[1].strip()
            elif line.startswith("delegation public key:"):
                pub = line.split(":")[1].strip()
        assert priv and pub, f"unexpected -gendelegationkey output: {out}"
        return priv, pub

    def run_test(self):
        node = self.nodes[0]
        self.min_stake = 100

        node.createwallet(wallet_name="owner", blsct=True)
        owner = node.get_wallet_rpc("owner")
        owner_address = owner.getnewaddress(label="", address_type="blsct")
        self.generatetoblsctaddress(node, 101, owner_address)

        operator_priv, operator_pub = self.gen_delegation_key()
        self.log.info(f"Operator delegation pubkey: {operator_pub}")

        self.test_argument_validation(owner, operator_pub)
        outhash = self.test_delegatestake(node, owner, owner_address, operator_pub)
        self.test_delegated_staker_tracking(node, operator_priv)
        self.test_fee_split_template(node, owner)
        self.test_revocation(node, owner, owner_address, outhash)

    def test_argument_validation(self, owner, operator_pub):
        self.log.info("Testing delegatestake argument validation")
        assert_raises_rpc_error(-8, "delegate_pubkey is not a valid G1 point",
                                owner.delegatestake, self.min_stake, "beef")
        assert_raises_rpc_error(-8, "delegate_pubkey is not a valid G1 point",
                                owner.delegatestake, self.min_stake, "00" * 48)
        assert_raises_rpc_error(-5, "Invalid reward_address",
                                owner.delegatestake, self.min_stake, operator_pub,
                                "notanaddress")
        assert_raises_rpc_error(-1, "A minimum of",
                                owner.delegatestake, self.min_stake - 1, operator_pub)

    def test_delegatestake(self, node, owner, owner_address, operator_pub):
        self.log.info("Testing delegatestake and the on-chain payload")

        reward_address = owner.getnewaddress(label="rewards", address_type="blsct")
        txid = owner.delegatestake(self.min_stake, operator_pub, reward_address)
        assert_equal(len(txid), 64)
        self.generatetoblsctaddress(node, 1, owner_address)

        entries = node.liststakedcommitmentsdata()
        delegated = [e for e in entries if e["predicate"]]
        assert_equal(len(delegated), 1)
        entry = delegated[0]
        # DATA predicate wrapping the delegation blob (magic + version).
        assert entry["predicate"].startswith("04"), entry["predicate"]
        assert DELEGATION_MAGIC_HEX in entry["predicate"], entry["predicate"]
        assert_equal(len(entry["commitment"]), 96)  # compressed G1 point

        # The owner's wallet still tracks it as its own staked commitment.
        own = owner.liststakedcommitments()
        assert_equal(len(own), 1)
        assert_equal(own[0]["commitment"], entry["commitment"])

        return entry["outhash"]

    def test_delegated_staker_tracking(self, node, operator_priv):
        self.log.info("Testing that a delegated staker decrypts and tracks the delegation")

        # No -chain argument: the node's navio.conf inside datadir already
        # selects blsctregtest, and the staker rejects setting both.
        args = [
            self.staker_path(),
            f"-datadir={self.nodes[0].datadir_path}",
            "-delegated",
            f"-delegationkey={operator_priv}",
            "-delegationrefresh=1",
            "-rpcwait",
            "-printtoconsole=1",
            "-nodebuglogfile",
        ]
        staker = subprocess.Popen(args, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)
        try:
            tracked = False
            for _ in range(600):
                line = staker.stdout.readline()
                if not line:
                    break
                self.log.debug(f"staker: {line.rstrip()}")
                if "Tracking 1 delegated commitment(s)" in line:
                    tracked = True
                    break
            assert tracked, "delegated staker did not report the delegation"
        finally:
            staker.kill()
            staker.wait()

    def test_fee_split_template(self, node, owner):
        self.log.info("Testing getblocktemplate operator fee split parameters")

        owner_addr = owner.getnewaddress(label="", address_type="blsct")
        operator_addr = owner.getnewaddress(label="", address_type="blsct")

        template = node.getblocktemplate({
            "rules": [""],
            "coinbasedest": owner_addr,
            "coinbasefeedest": operator_addr,
            "coinbasefeebps": 500,
        })
        assert "staked_commitments" in template

        assert_raises_rpc_error(-8, "coinbasefeebps must be in [0, 10000]",
                                node.getblocktemplate,
                                {"rules": [""], "coinbasedest": owner_addr,
                                 "coinbasefeedest": operator_addr,
                                 "coinbasefeebps": 10001})
        assert_raises_rpc_error(-8, "coinbasefeedest requires coinbasefeebps",
                                node.getblocktemplate,
                                {"rules": [""], "coinbasedest": owner_addr,
                                 "coinbasefeedest": operator_addr})

    def test_revocation(self, node, owner, owner_address, outhash):
        self.log.info("Testing revocation via stakeunlock")

        txid = owner.stakeunlock(self.min_stake)
        assert_equal(len(txid), 64)
        self.generatetoblsctaddress(node, 1, owner_address)

        entries = node.liststakedcommitmentsdata()
        assert_equal([e for e in entries if e["outhash"] == outhash], [])


if __name__ == "__main__":
    NavioBlsctColdStakingTest(__file__).main()
