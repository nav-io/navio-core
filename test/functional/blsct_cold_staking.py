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
import queue
import re
import subprocess
import threading
import time

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

# Seconds (before --timeout-factor) a test waits for a staker log line,
# producing a block included.
STAKER_TIMEOUT = 120



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

    def spawn_staker(self, extra_args, delegated=True):
        args = [
            self.staker_path(),
            f"-datadir={self.nodes[0].datadir_path}",
        ] + (["-delegated", "-delegationrefresh=1"] if delegated else []) + [
            "-rpcwait",
            "-printtoconsole=1",
            "-nodebuglogfile",
        ] + extra_args
        staker = subprocess.Popen(args, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)
        # readline() on the pipe blocks for as long as the staker stays quiet,
        # so a reader thread feeds the lines to a queue that staker_lines()
        # reads with a deadline. None marks the end of the output.
        staker.lines = queue.Queue()

        def pump():
            for line in staker.stdout:
                staker.lines.put(line)
            staker.lines.put(None)
        threading.Thread(target=pump, daemon=True).start()
        return staker

    def staker_lines(self, staker, timeout, waiting_for):
        """Yield staker output lines until it ends, raising AssertionError
        (naming waiting_for) once timeout seconds, scaled by
        --timeout-factor, pass first."""
        timeout *= self.options.timeout_factor
        deadline = time.monotonic() + timeout
        while True:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise queue.Empty
                line = staker.lines.get(timeout=remaining)
            except queue.Empty:
                raise AssertionError(f"staker timed out after {timeout:g}s waiting for {waiting_for}") from None
            if line is None:
                return
            self.log.debug(f"staker: {line.rstrip()}")
            yield line

    def wait_for_staker_line(self, staker, needles, timeout=STAKER_TIMEOUT):
        """Read staker output until a line containing any needle appears.
        Returns the matching needle, or None if the output ends first."""
        for line in self.staker_lines(staker, timeout, f"a line containing one of {needles}"):
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

        # Funded now, while the owner still has spendable coins; used by
        # test_owner_staker_pays_reward_address at the end.
        node.createwallet(wallet_name="selfstaker", blsct=True)
        owner.sendtoblsctaddress(node.get_wallet_rpc("selfstaker").getnewaddress(label="", address_type="blsct"), 2 * self.min_stake)
        node.createwallet(wallet_name="mixedstaker", blsct=True)
        owner.sendtoblsctaddress(node.get_wallet_rpc("mixedstaker").getnewaddress(label="", address_type="blsct"), 3 * self.min_stake)
        self.generatetoblsctaddress(node, 1, owner_address)

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
        self.test_owner_staker_pays_reward_address(node)
        self.test_mixed_wallet_staker(node)

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
            found = self.wait_for_staker_line(staker, ["(ACCEPTED)"])
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

    def test_owner_staker_pays_reward_address(self, node):
        """The owner's own wallet-mode staker may stake a commitment the wallet
        delegated. The block reward must then go to the delegation's reward
        address, not to the staker's -coinbasedest, so listdelegations
        accounts for it."""
        self.log.info("Testing a wallet-mode staker staking the wallet's own delegated stake")

        # A wallet whose only stake is a delegation (to an operator key of its
        # own), so whichever commitment the staker produces with, the reward
        # belongs at the delegation's reward address.
        wallet = node.get_wallet_rpc("selfstaker")
        _, operator_pub = self.gen_delegation_key()
        reward_address = wallet.getnewaddress(label="rewards", address_type="blsct")
        wallet.delegatestake(self.min_stake, operator_pub, reward_address)
        self.generatetoblsctaddress(node, 10, wallet.getnewaddress(label="", address_type="blsct"))

        delegations = wallet.listdelegations()
        assert_equal(len(delegations), 1)
        assert_equal(delegations[0]["reward_address"], reward_address)
        assert_equal([c["commitment"] for c in wallet.liststakedcommitments()], [delegations[0]["commitment"]])
        assert_equal(delegations[0]["rewards_count"], 0)

        height_before = node.getblockcount()
        coinbase_dest = wallet.getnewaddress(label="staker", address_type="blsct")

        staker = self.spawn_staker(["-wallet=selfstaker", f"-coinbasedest={coinbase_dest}"], delegated=False)
        try:
            found = self.wait_for_staker_line(staker, ["(ACCEPTED)"])
            assert found, "wallet-mode staker did not produce an accepted block"
        finally:
            staker.kill()
            staker.wait()

        self.wait_until(lambda: node.getblockcount() > height_before)
        node.syncwithvalidationinterfacequeue()

        deleg = wallet.listdelegations()[0]
        assert_greater_than(deleg["rewards_count"], 0)
        assert_greater_than(deleg["rewards_received"], 0)
        # Nothing was paid to -coinbasedest.
        assert_equal([r for r in wallet.liststakingrewards() if r["address"] == coinbase_dest], [])

    def test_mixed_wallet_staker(self, node):
        """A wallet-mode staker whose wallet holds both a plain stake and a
        delegated one pays -coinbasedest for the former and the reward address
        for the latter. It looks the delegations up when it starts and then
        only when the wallet's staked-commitment set changes (a delegation
        added, a stake unlocked), not on every cycle."""
        self.log.info("Testing a wallet-mode staker with a plain and a delegated stake")

        wallet = node.get_wallet_rpc("mixedstaker")
        wallet.stakelock(self.min_stake)
        self.generatetoblsctaddress(node, 10, wallet.getnewaddress(label="", address_type="blsct"))
        plain_commitment = [c["commitment"] for c in wallet.liststakedcommitments()]
        assert_equal(len(plain_commitment), 1)
        plain_commitment = plain_commitment[0]
        assert_equal(wallet.listdelegations(), [])

        coinbase_dest = wallet.getnewaddress(label="staker", address_type="blsct")
        reward_address = wallet.getnewaddress(label="rewards", address_type="blsct")
        refresh_line = "Refreshed own delegations:"
        staked_with_re = re.compile(r"staked with commitment ([0-9a-f]+), reward to (\S+)")

        class Session:
            """A running staker and what it has logged so far."""
            def __init__(session):
                session.proc = self.spawn_staker(["-wallet=mixedstaker", f"-coinbasedest={coinbase_dest}"], delegated=False)
                session.refresh = []
                session.staked_with = []

            def read_until(session, condition, timeout=STAKER_TIMEOUT):
                """Consume output until condition() holds, checking it after
                each refresh or staked-block line."""
                for line in session.lines(timeout):
                    if refresh_line in line:
                        session.refresh.append(line.split(refresh_line)[1].strip())
                    elif m := staked_with_re.search(line):
                        session.staked_with.append((m.group(1), m.group(2)))
                    else:
                        continue
                    if condition():
                        return
                raise AssertionError(f"staker output ended early; {session.progress()}")

            def lines(session, timeout):
                """staker_lines(), reporting progress so far on a timeout."""
                try:
                    yield from self.staker_lines(session.proc, timeout, "a condition")
                except AssertionError as e:
                    raise AssertionError(f"{e}; {session.progress()}") from None

            def progress(session):
                return f"refresh={session.refresh} staked_with={session.staked_with}"

            def stop(session):
                session.proc.kill()
                session.proc.wait()

        def expected_dest(commitment, delegated_commitment):
            return reward_address if commitment == delegated_commitment else coinbase_dest

        # Only the plain stake exists: its blocks pay -coinbasedest, and the
        # delegations are looked up once for all of them.
        session = Session()
        try:
            session.read_until(lambda: len(session.staked_with) >= 3)
            assert_equal(session.refresh, ["0 of 1 staked commitment(s) delegated."])
            assert_equal(set(session.staked_with), {(plain_commitment, coinbase_dest)})

            # Delegate a second stake while the staker runs. It enters the
            # staked set once the staker mines it, which triggers exactly one
            # more lookup.
            _, operator_pub = self.gen_delegation_key()
            wallet.delegatestake(self.min_stake, operator_pub, reward_address)
            session.read_until(lambda: len(session.refresh) >= 2)
            assert_equal(session.refresh[1], "1 of 2 staked commitment(s) delegated.")
            seen_before = len(session.staked_with)
            session.read_until(lambda: len(session.staked_with) >= seen_before + 3)
            assert_equal(len(session.refresh), 2)
        finally:
            session.stop()

        delegated_commitment = wallet.listdelegations()[0]["commitment"]
        assert_equal(sorted(c["commitment"] for c in wallet.liststakedcommitments()), sorted([plain_commitment, delegated_commitment]))
        for commitment, dest in session.staked_with:
            assert_equal(dest, expected_dest(commitment, delegated_commitment))

        # The staker stakes with the first commitment liststakedcommitments
        # returns that yields a block, and that order follows the wallet's
        # salted output map. Restart the node until each stake comes first in
        # turn, so both are seen staking in the mixed wallet. Each fresh
        # staker also starts with an empty lookup and fetches it once.
        for wanted in (plain_commitment, delegated_commitment):
            for _ in range(60):
                self.restart_node(0)
                node = self.nodes[0]
                node.loadwallet("mixedstaker")
                wallet = node.get_wallet_rpc("mixedstaker")
                if wallet.liststakedcommitments()[0]["commitment"] == wanted:
                    break
            else:
                raise AssertionError(f"commitment {wanted} never came first")

            node.syncwithvalidationinterfacequeue()
            paid_before = {d["commitment"]: d["rewards_count"] for d in wallet.listdelegations()}
            coinbase_paid_before = sum(r["count"] for r in wallet.liststakingrewards() if r["address"] == coinbase_dest)
            session = Session()
            try:
                session.read_until(lambda: any(c == wanted for c, _ in session.staked_with))
                assert_equal(session.refresh, ["1 of 2 staked commitment(s) delegated."])
            finally:
                session.stop()
            for commitment, dest in session.staked_with:
                assert_equal(dest, expected_dest(commitment, delegated_commitment))

            node.syncwithvalidationinterfacequeue()
            if wanted == delegated_commitment:
                assert_greater_than(wallet.listdelegations()[0]["rewards_count"], paid_before[delegated_commitment])
            else:
                assert_greater_than(sum(r["count"] for r in wallet.liststakingrewards() if r["address"] == coinbase_dest), coinbase_paid_before)

        # A staked commitment disappearing also triggers a lookup. The unlock
        # spends stakes in the mempool (re-staking any remainder), which can
        # leave the staker nothing to stake until it confirms, so mine that
        # block here.
        session = Session()
        try:
            session.read_until(lambda: len(session.staked_with) >= 1)
            assert_equal(session.refresh, ["1 of 2 staked commitment(s) delegated."])
            wallet.stakeunlock(self.min_stake)
            self.generatetoblsctaddress(node, 1, wallet.getnewaddress(label="", address_type="blsct"))
            session.read_until(lambda: len(session.refresh) >= 2)
            assert session.refresh[1].endswith("of 1 staked commitment(s) delegated."), session.refresh
            # Several more blocks (and many more cycles), no more lookups.
            seen_before = len(session.staked_with)
            session.read_until(lambda: len(session.staked_with) >= seen_before + 3)
            assert_equal(len(session.refresh), 2)
        finally:
            session.stop()

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
