#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test delegated cold staking: delegatestake RPC, on-chain delegation payload,
liststakedcommitmentsdata scan, owner-side visibility (listdelegations,
delegated balances), redelegation, reward compounding, fee-split block
templates, end-to-end delegated block production and revocation."""

import json
import os.path
import subprocess

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

# DataPredicate serialization: <DATA op (0x04)> <compact size> <payload>.
# The payload starts with the delegation magic "NVDG" + version 0x01.
DELEGATION_MAGIC_HEX = "4e56444701"

# Well-formed blsctregtest addresses whose view key, spend key, or both are the
# identity (point at infinity). They decode fine and validateaddress calls them
# valid, but outputs paid to them are anyone-can-spend, so a delegate must never
# be asked to send block rewards there.
NULL_KEY_ADDRESS = "rnv1cqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwwvmtas"
NULL_VIEW_KEY_ADDRESS = "rnv1cqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp9l36wnnr97hjsnf2cuvf756cr7rdzxyl9m5hyz6zn368ut3htzcd327s0le0gdwl7e67q9dkgkxhvmdqls40d"
NULL_SPEND_KEY_ADDRESS = "rnv1jlca8fe3jltegf54vwxyl2dvplpk3rz0ja6tjpdpfcar79cm43vxc40g8luh5xh0lva0qzkmytrthsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqma0f57ul"
NULL_KEY_ADDRESSES = (NULL_KEY_ADDRESS, NULL_VIEW_KEY_ADDRESS, NULL_SPEND_KEY_ADDRESS)


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

    def spawn_staker(self, extra_args):
        args = [
            self.staker_path(),
            f"-datadir={self.nodes[0].datadir_path}",
            "-delegated",
            "-delegationrefresh=1",
            "-rpcwait",
            "-printtoconsole=1",
            "-nodebuglogfile",
        ] + extra_args
        return subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)

    def wait_for_staker_line(self, staker, needles, max_lines=600):
        """Read staker stdout until a line containing any needle appears.
        Returns the matching needle or None."""
        for _ in range(max_lines):
            line = staker.stdout.readline()
            if not line:
                return None
            self.log.debug(f"staker: {line.rstrip()}")
            for needle in needles:
                if needle in line:
                    return needle
        return None

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
        outhash, reward_address = self.test_delegatestake(node, owner, owner_address, operator_pub)
        self.test_owner_visibility(node, owner, operator_pub, reward_address)
        self.test_delegated_staker_tracking(node, operator_priv)
        self.test_wrong_key_sees_nothing(node)
        other_operator_pub = self.test_consolidation_grouping(node, owner, owner_address, operator_pub, reward_address)
        self.test_redelegation(node, owner, owner_address, operator_pub, other_operator_pub, reward_address)
        self.test_compounding(node, owner, owner_address, operator_pub, reward_address)
        self.test_fee_split_template(node, owner)
        self.test_delegated_block_production(node, owner, operator_priv, reward_address)
        self.test_revocation(node, owner, owner_address, operator_pub)

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
        out_hash = owner.delegatestake(self.min_stake, operator_pub, reward_address)
        assert_equal(len(out_hash), 64)
        self.generatetoblsctaddress(node, 1, owner_address)

        entries = node.liststakedcommitmentsdata()
        delegated = [e for e in entries if e["predicate"]]
        assert_equal(len(delegated), 1)
        entry = delegated[0]
        # DATA predicate wrapping the delegation blob (magic + version).
        assert entry["predicate"].startswith("04"), entry["predicate"]
        assert DELEGATION_MAGIC_HEX in entry["predicate"], entry["predicate"]
        assert_equal(len(entry["commitment"]), 96)  # compressed G1 point

        # Height/confirmations let an operator judge output maturity.
        tip_height = node.getblockcount()
        assert_equal(entry["height"] + entry["confirmations"] - 1, tip_height)
        assert_greater_than(entry["confirmations"], 0)

        # Smoke test: a repeated call at the same tip returns the identical
        # result. (This holds with or without the per-tip cache — the cache
        # itself is not observable from here.)
        assert_equal(node.liststakedcommitmentsdata(), entries)

        # The owner's wallet still tracks it as its own staked commitment.
        own = owner.liststakedcommitments()
        assert_equal(len(own), 1)
        assert_equal(own[0]["commitment"], entry["commitment"])

        return entry["outhash"], reward_address

    def test_owner_visibility(self, node, owner, operator_pub, reward_address):
        self.log.info("Testing listdelegations and delegated balance reporting")

        delegations = owner.listdelegations()
        assert_equal(len(delegations), 1)
        d = delegations[0]
        assert_equal(d["amount"], Decimal(self.min_stake))
        assert_equal(d["delegate_pubkey"], operator_pub)
        assert_equal(d["reward_address"], reward_address)
        assert_equal(d["reward_address_is_mine"], True)
        assert_greater_than(d["confirmations"], 0)
        # No delegated block has been produced yet.
        assert_equal(d["rewards_received"], 0)
        assert_equal(d["rewards_count"], 0)

        balances = owner.getbalances()["mine"]
        assert_equal(balances["delegated_staked_commitment_balance"], Decimal(self.min_stake))
        # The delegated stake is part of (not additional to) the staked total.
        assert_greater_than_or_equal(balances["staked_commitment_balance"],
                                     balances["delegated_staked_commitment_balance"])

    def test_delegated_staker_tracking(self, node, operator_priv):
        self.log.info("Testing that a delegated staker decrypts and tracks the delegation")

        # Pass the key via -delegationkeyfile (the recommended way: a key on
        # the command line is visible in the process list) and request a
        # stats file.
        keyfile = os.path.join(self.options.tmpdir, "delegation.key")
        with open(keyfile, "w", encoding="utf8") as f:
            f.write(operator_priv + "\n")
        self.statsfile = os.path.join(self.options.tmpdir, "delegation-stats.json")

        staker = self.spawn_staker([f"-delegationkeyfile={keyfile}",
                                    f"-statsfile={self.statsfile}"])
        try:
            found = self.wait_for_staker_line(staker, ["Tracking 1 delegated commitment(s)"])
            assert found, "delegated staker did not report the delegation"
            # The stats file is written right after the "Tracking" log line;
            # don't race the kill against it.
            self.wait_until(lambda: os.path.exists(self.statsfile))
        finally:
            staker.kill()
            staker.wait()

        # The stats file was written on the delegation refresh and lists the
        # delegation with no blocks yet.
        with open(self.statsfile, encoding="utf8") as f:
            stats = json.load(f)
        assert_equal(len(stats["delegations"]), 1)
        assert_equal(stats["delegations"][0]["blocks_accepted"], 0)

        # Both key sources must not be combined.
        proc = subprocess.run([self.staker_path(), f"-datadir={self.nodes[0].datadir_path}",
                               "-delegated", "-delegationkey=00", f"-delegationkeyfile={keyfile}"],
                              capture_output=True, text=True)
        # A clean EXIT_FAILURE, not an abort: an uncaught exception leaves the
        # message to the C++ runtime, which prints it on libstdc++ and nothing
        # at all on the MSVC runtime.
        assert_equal(proc.returncode, 1)
        assert "mutually exclusive" in proc.stderr + proc.stdout

    def test_wrong_key_sees_nothing(self, node):
        self.log.info("Testing that an operator with a different key sees no delegations")
        wrong_priv, _ = self.gen_delegation_key()
        staker = self.spawn_staker([f"-delegationkey={wrong_priv}"])
        try:
            found = self.wait_for_staker_line(staker, ["Tracking 0 delegated commitment(s)"])
            assert found, "staker with an unrelated key should track zero delegations"
        finally:
            staker.kill()
            staker.wait()

    def test_consolidation_grouping(self, node, owner, owner_address, operator_pub, reward_address):
        """Consolidation must only fold stakes sharing the same delegation
        identity (delegate key + reward address), and plain stakes must only
        fold with plain stakes."""
        self.log.info("Testing delegation-aware stake consolidation")

        def snapshot():
            entries = node.liststakedcommitmentsdata()
            plain = [e for e in entries if not e["predicate"]]
            delegated = [e for e in entries if e["predicate"]]
            return plain, delegated

        # Starting point: one delegated stake (min_stake to operator_pub).
        plain, delegated = snapshot()
        assert_equal((len(plain), len(delegated)), (0, 1))

        # A plain stakelock must NOT touch the delegated stake.
        owner.stakelock(self.min_stake)
        self.generatetoblsctaddress(node, 1, owner_address)
        plain, delegated = snapshot()
        assert_equal((len(plain), len(delegated)), (1, 1))
        first_delegated = delegated[0]["outhash"]

        # A second plain stakelock consolidates with the first plain stake
        # only; the delegated stake still stays untouched.
        owner.stakelock(self.min_stake)
        self.generatetoblsctaddress(node, 1, owner_address)
        plain, delegated = snapshot()
        assert_equal((len(plain), len(delegated)), (1, 1))
        assert_equal(delegated[0]["outhash"], first_delegated)

        # Delegating again with the SAME delegate and reward address
        # consolidates with the existing delegation (one bigger delegated
        # stake, new outhash), leaving the plain stake alone.
        owner.delegatestake(self.min_stake, operator_pub, reward_address)
        self.generatetoblsctaddress(node, 1, owner_address)
        plain, delegated = snapshot()
        assert_equal((len(plain), len(delegated)), (1, 1))
        assert delegated[0]["outhash"] != first_delegated

        # Delegating to a DIFFERENT delegate creates a separate delegated
        # stake instead of folding into the existing one.
        _, other_operator_pub = self.gen_delegation_key()
        owner.delegatestake(self.min_stake, other_operator_pub)
        self.generatetoblsctaddress(node, 1, owner_address)
        plain, delegated = snapshot()
        assert_equal((len(plain), len(delegated)), (1, 2))

        # Wallet-side accounting agrees: three commitments total worth
        # 5 * min_stake (2 plain consolidated + 2 same-delegation consolidated
        # + 1 other-delegation).
        own = owner.liststakedcommitments()
        assert_equal(len(own), 3)
        assert_equal(len(owner.listdelegations()), 2)

        return other_operator_pub

    def test_redelegation(self, node, owner, owner_address, operator_pub, other_operator_pub, reward_address):
        self.log.info("Testing redelegatestake (operator swap in one transaction)")

        _, unused_pub = self.gen_delegation_key()
        assert_raises_rpc_error(-8, "No stakes are delegated to from_delegate_pubkey",
                                owner.redelegatestake, unused_pub, operator_pub)

        # An explicit reward_address is validated here the same way
        # delegatestake validates it. This RPC reaches that check only once
        # real delegations exist, which is why it is pinned here rather than in
        # blsct_spend_rpc_guards.py.
        for null_address in NULL_KEY_ADDRESSES:
            assert_raises_rpc_error(-5, "reward_address has null keys",
                                    owner.redelegatestake, other_operator_pub,
                                    operator_pub, null_address)

        # Move the stake delegated to other_operator over to operator_pub,
        # unifying it with the existing delegation (same delegate + reward
        # address). The commitments never leave the staking set.
        out_hash = owner.redelegatestake(other_operator_pub, operator_pub, reward_address)
        assert_equal(len(out_hash), 64)
        self.generatetoblsctaddress(node, 1, owner_address)

        delegations = owner.listdelegations()
        assert_equal(len(delegations), 1)
        assert_equal(delegations[0]["delegate_pubkey"], operator_pub)
        assert_equal(delegations[0]["reward_address"], reward_address)
        # 2 x min_stake previously under operator_pub + 1 x min_stake moved.
        assert_equal(delegations[0]["amount"], Decimal(3 * self.min_stake))

        # The plain stake was not folded into the redelegation.
        entries = node.liststakedcommitmentsdata()
        plain = [e for e in entries if not e["predicate"]]
        delegated = [e for e in entries if e["predicate"]]
        assert_equal((len(plain), len(delegated)), (1, 1))

    def test_compounding(self, node, owner, owner_address, operator_pub, reward_address):
        self.log.info("Testing compounddelegations")

        before = owner.listdelegations()[0]["amount"]
        spendable = owner.getbalances()["mine"]["trusted"]
        assert_greater_than(spendable, 2)

        # Below min_amount: nothing to do.
        assert_equal(owner.compounddelegations(operator_pub, spendable + 100), None)

        out_hash = owner.compounddelegations()
        assert_equal(len(out_hash), 64)
        self.generatetoblsctaddress(node, 1, owner_address)

        delegations = owner.listdelegations()
        assert_equal(len(delegations), 1)
        assert_greater_than(delegations[0]["amount"], before)
        assert_equal(delegations[0]["delegate_pubkey"], operator_pub)
        assert_equal(delegations[0]["reward_address"], reward_address)

        balances = owner.getbalances()["mine"]
        assert_equal(balances["delegated_staked_commitment_balance"], delegations[0]["amount"])

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

    def test_delegated_block_production(self, node, owner, operator_priv, reward_address):
        """End to end: a wallet-less operator staker produces an accepted
        block with the delegated stake; the reward lands at the owner's reward
        address and the operator fee output at the operator's address."""
        self.log.info("Testing end-to-end delegated block production with an operator fee")

        node.createwallet(wallet_name="operator", blsct=True)
        operator_wallet = node.get_wallet_rpc("operator")
        operator_addr = operator_wallet.getnewaddress(label="", address_type="blsct")

        height_before = node.getblockcount()
        rewards_before = owner.listdelegations()[0]["rewards_received"]
        self.e2e_reward_address = reward_address

        staker = self.spawn_staker([f"-delegationkey={operator_priv}",
                                    "-operatorfee=1000",
                                    f"-operatoraddress={operator_addr}",
                                    f"-statsfile={self.statsfile}"])

        def stats_show_block():
            try:
                with open(self.statsfile, encoding="utf8") as f:
                    stats = json.load(f)
                return stats["delegations"][0]["blocks_accepted"] > 0
            except (FileNotFoundError, json.JSONDecodeError, KeyError, IndexError):
                return False

        try:
            found = self.wait_for_staker_line(staker, ["(ACCEPTED)"], max_lines=3000)
            assert found, "delegated staker did not produce an accepted block"
            # The stats file is updated right after the acceptance log line;
            # don't race the kill against it.
            self.wait_until(stats_show_block)
        finally:
            staker.kill()
            staker.wait()

        self.wait_until(lambda: node.getblockcount() > height_before)

        # The per-delegation accounting recorded the produced block.
        with open(self.statsfile, encoding="utf8") as f:
            stats = json.load(f)
        assert_equal(len(stats["delegations"]), 1)
        assert_greater_than(stats["delegations"][0]["blocks_accepted"], 0)
        assert stats["delegations"][0]["last_block_hash"]

        # 90% of the reward went to the owner's reward address...
        owner.keypoolrefill()
        deleg = owner.listdelegations()[0]
        assert_greater_than(deleg["rewards_received"], rewards_before)
        assert_greater_than(deleg["rewards_count"], 0)

        # ...and the 10% operator fee arrived at the operator's own wallet
        # (as an immature coinbase output).
        operator_balances = operator_wallet.getbalances()["mine"]
        operator_total = operator_balances["immature"] + operator_balances["trusted"] + operator_balances["untrusted_pending"]
        assert_greater_than(operator_total, 0)

        # liststakingrewards tracks both kinds of staking rewards: the
        # delegated ones (reward address of an active delegation) and the
        # wallet's own, non-delegated coinbase rewards.
        rewards = {r["address"]: r for r in owner.liststakingrewards()}
        delegated_rewards = rewards[reward_address]
        assert_equal(delegated_rewards["from_delegation"], True)
        assert_greater_than(delegated_rewards["amount"], 0)
        assert_greater_than(delegated_rewards["last_height"], height_before)
        own_rewards = [r for r in rewards.values() if not r["from_delegation"]]
        assert_greater_than(len(own_rewards), 0)
        assert_greater_than(own_rewards[0]["amount"], 0)
        assert_greater_than(own_rewards[0]["count"], 0)

    def test_revocation(self, node, owner, owner_address, operator_pub):
        self.log.info("Testing revocation via stakeunlock")

        # Unstake everything: delegated or not, the spend key revokes it all,
        # and the staked set ends up empty.
        staked = owner.getbalances()["mine"]["staked_commitment_balance"]
        out_hash = owner.stakeunlock(staked)
        assert_equal(len(out_hash), 64)
        self.generatetoblsctaddress(node, 1, owner_address)

        assert_equal(node.liststakedcommitmentsdata(), [])
        assert_equal(owner.listdelegations(), [])
        assert_equal(owner.getbalances()["mine"]["delegated_staked_commitment_balance"], 0)

        # Delegating again after a revocation works: the delegation died with
        # the commitment, not with the wallet or the operator key.
        owner.delegatestake(self.min_stake, operator_pub)
        self.generatetoblsctaddress(node, 1, owner_address)
        assert_equal(len(owner.listdelegations()), 1)

        # Reward history survives revocation: the rewards earned under the
        # old (now revoked) delegation are still listed, no longer tied to an
        # active delegation. The new delegation uses a fresh reward address,
        # so the old address must not be flagged.
        new_reward_address = owner.listdelegations()[0]["reward_address"]
        rewards = {r["address"]: r for r in owner.liststakingrewards()}
        assert self.e2e_reward_address in rewards
        assert new_reward_address != self.e2e_reward_address
        assert_equal(rewards[self.e2e_reward_address]["from_delegation"], False)
        assert_greater_than(rewards[self.e2e_reward_address]["amount"], 0)


if __name__ == "__main__":
    NavioBlsctColdStakingTest(__file__).main()
