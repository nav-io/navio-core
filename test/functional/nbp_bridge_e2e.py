#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end functional test of the NBP bridge prototype on blsctregtest.

Covers the full Navio-side protocol loop (navio-bridge-protocol DESIGN.md):

  1. Guardian registration (mock SPP) and committee snapshot lookahead
  2. Checkpoint signing (2/3 bond-weight quorum), embedding, dynamic finality
  3. Peg-in: attested deposit -> confidential mint -> maturity gating
  4. Peg-out: burn -> PegOutEvent -> PegOutRoot committed by a checkpoint
  5. Fraud window: challenge -> committee resolution (reject) and the
     R_max fail-safe (timeout revoke + re-mint of the same deposit id)
  6. Dynamic finality: a heavier fork below the finalized checkpoint is
     not adopted
  7. Peg solvency invariant: vault-side view (deposits attested and not
     revoked) >= circulating wrapped supply

blsctregtest NBP parameters (kernel/chainparams.cpp): E=5, P=3, M=6,
R_max=20, q=2, MIN_BOND=1000, CHALLENGE_BOND=100, U=50.
"""

import os
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

ETH_CHAIN_ID = 31337
TOKEN = "aa" * 20
E = 5
P = 3
PERIOD_BLOCKS = E * P
BRIDGE_HEIGHT = 1
MINT_MATURITY = 6
RESOLUTION_WINDOW = 20
FINALITY_BURIAL = 2
MIN_BOND = 1000
CHALLENGE_BOND = 100


class NbpBridgeE2ETest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def mine(self, n):
        """Mine n blocks on node0 in capped batches, syncing node1 if connected."""
        node = self.nodes[0]
        while n > 0:
            batch = min(n, 10)
            self.generatetoblsctaddress(node, batch, self.funder_addr, sync_fun=self.no_op)
            n -= batch
        if self.node1_connected:
            self.sync_blocks()

    def mine_to_height(self, h):
        cur = self.nodes[0].getblockcount()
        if h > cur:
            self.mine(h - cur)

    def epoch_of(self, height):
        return (height - BRIDGE_HEIGHT) // E

    def boundary_of(self, epoch):
        return BRIDGE_HEIGHT + (epoch + 1) * E - 1

    def sign_quorum(self, context, payload, signers=None):
        """Sign payload with guardian wallets, return (bitfield_hex, agg_sig)."""
        committee = self.nodes[0].getnbpcommittee()
        members = [m["pubkey"] for m in committee["members"]]
        assert len(members) > 0, "no committee for current period"
        signers = signers if signers is not None else self.guardians
        sigs = []
        bits = 0
        signer_pks = {}
        for g in signers:
            res = g.nbpsignmessage(context, payload)
            signer_pks[res["public_key"]] = res["signature"]
        for i, pk in enumerate(members):
            if pk in signer_pks:
                bits |= 1 << i
                sigs.append(signer_pks[pk])
        assert len(sigs) == len(signers), "signer not in committee"
        nbytes = (len(members) + 7) // 8
        bitfield = bits.to_bytes(nbytes, "little").hex()
        agg = self.guardians[0].nbpaggregatesigs(sigs)
        return bitfield, agg

    def embed_checkpoint(self, epoch, signers=None):
        """Assemble + embed a checkpoint for `epoch`, mine 1 block."""
        node = self.nodes[0]
        msg = node.getnbpcheckpointmsg(epoch)
        bitfield, agg = self.sign_quorum("checkpoint", msg["cp_bytes"], signers)
        node.submitnbpcheckpoint(epoch, msg["block_hash"], msg["block_height"],
                                 msg["committee_root"], msg["pegout_root"], bitfield, agg)
        self.mine(1)
        rec = node.getnbpcheckpoint(epoch)
        assert_equal(rec["block_hash"], msg["block_hash"])
        return rec

    def attest_deposit(self, deposit_id, amount, claim_commit, signers=None):
        node = self.nodes[0]
        att = node.getnbpattestationmsg(ETH_CHAIN_ID, deposit_id, TOKEN, amount, claim_commit)
        return self.sign_quorum("attestation", att, signers)

    def assert_peg_solvency(self):
        """PegSolvency (Lean L2 / TLA+ invariant): simulated vault balance
        (sum of attested deposits minus withdrawals authorized by burns)
        >= circulating wrapped supply on Navio."""
        info = self.nodes[0].getnbptokeninfo(ETH_CHAIN_ID, TOKEN)
        vault = self.vault_locked - self.vault_withdrawn
        circulating = Decimal(str(info["minted"])) - Decimal(str(info["burned"]))
        assert_greater_than_or_equal(vault, circulating)
        assert_greater_than_or_equal(circulating, 0)

    def run_test(self):
        node = self.nodes[0]
        self.node1_connected = True
        # Simulated Ethereum vault accounting for the solvency invariant.
        self.vault_locked = Decimal(0)
        self.vault_withdrawn = Decimal(0)

        self.log.info("Set up wallets and fund guardians")
        node.createwallet(wallet_name="funder", blsct=True)
        funder = node.get_wallet_rpc("funder")
        self.funder_addr = funder.getnewaddress(label="", address_type="blsct")

        # First block carries the initial supply; mature it.
        self.mine(101)

        self.guardians = []
        for i in range(3):
            node.createwallet(wallet_name=f"g{i}", blsct=True)
            g = node.get_wallet_rpc(f"g{i}")
            addr = g.getnewaddress(label="", address_type="blsct")
            funder.sendtoblsctaddress(addr, MIN_BOND + 50)
            self.guardians.append(g)
        node.createwallet(wallet_name="user", blsct=True)
        user = node.get_wallet_rpc("user")
        funder.sendtoblsctaddress(user.getnewaddress(label="", address_type="blsct"), 100)
        self.mine(2)

        self.log.info("Register 3 guardians (mock SPP)")
        for g in self.guardians:
            g.nbpregisterguardian(MIN_BOND)
        self.mine(1)
        guardians = node.getnbpguardians()
        assert_equal(len(guardians), 3)
        assert all(e["status"] == "active" for e in guardians)
        reg_height = node.getblockcount()

        self.log.info("Mine to a period whose committee contains the guardians")
        # Snapshot at the last block of period p covers period p+2; the
        # first snapshot taken after registration is the first with members.
        reg_period = self.epoch_of(reg_height) // P
        active_period = reg_period + 2
        active_height = BRIDGE_HEIGHT + active_period * PERIOD_BLOCKS
        self.mine_to_height(active_height)
        committee = node.getnbpcommittee()
        assert_equal(len(committee["members"]), 3)

        self.log.info("Embed a checkpoint and reach dynamic finality")
        epoch = self.epoch_of(node.getblockcount()) - 1
        self.embed_checkpoint(epoch)
        self.mine(FINALITY_BURIAL)
        fin = node.getnbpfinality()
        assert_equal(fin["finalized"], True)
        assert_equal(fin["block_height"], self.boundary_of(epoch))
        final_hash = fin["block_hash"]
        final_height = fin["block_height"]

        self.log.info("Quorum below 2/3 weight is rejected")
        bad_epoch = self.epoch_of(node.getblockcount()) - 1
        if node.getblockcount() == self.boundary_of(bad_epoch + 1):
            bad_epoch += 1
        msg = node.getnbpcheckpointmsg(bad_epoch)
        bitfield, agg = self.sign_quorum("checkpoint", msg["cp_bytes"], signers=self.guardians[:1])
        node.submitnbpcheckpoint(bad_epoch, msg["block_hash"], msg["block_height"],
                                 msg["committee_root"], msg["pegout_root"], bitfield, agg)
        self.mine(1)
        # The miner drops the underweight checkpoint instead of embedding it.
        assert_raises_rpc_error(-8, "no checkpoint for epoch", node.getnbpcheckpoint, bad_epoch)

        self.log.info("Peg-in: attested deposit mints confidential wrapped tokens")
        deposit_id = "11" * 32
        amount = 50
        r_hex = "22" * 32
        claim = user.nbpgetclaimcommit(r_hex)
        self.vault_locked += Decimal(amount)  # ERC20 escrowed on Ethereum
        bitfield, agg = self.attest_deposit(deposit_id, amount, claim["claim_commit"])
        user.nbpclaimdeposit(ETH_CHAIN_ID, TOKEN, deposit_id, amount, r_hex, bitfield, agg)
        self.mine(1)
        dep = node.getnbpdeposit(deposit_id)
        assert_equal(dep["status"], "minted")
        assert_equal(Decimal(str(dep["amount"])), Decimal(amount))
        info = node.getnbptokeninfo(ETH_CHAIN_ID, TOKEN)
        assert_equal(Decimal(str(info["minted"])), Decimal(amount))
        self.assert_peg_solvency()
        token_id = info["token_id"]

        self.log.info("Duplicate deposit id is rejected")
        assert_raises_rpc_error(None, "nbp-mint-dup-deposit", user.nbpclaimdeposit,
                                ETH_CHAIN_ID, TOKEN, deposit_id, amount, r_hex, bitfield, agg)

        self.log.info("Minted outputs are unspendable during the fraud window")
        user_token_addr = user.getnewaddress(label="tok", address_type="blsct")
        assert_raises_rpc_error(None, "nbp-mint-immature",
                                user.sendtokentoblsctaddress, token_id, user_token_addr, 10)
        self.mine(MINT_MATURITY)
        user.sendtokentoblsctaddress(token_id, user_token_addr, 10)
        self.mine(1)

        self.log.info("Peg-out: burn declares an Ethereum withdrawal")
        eth_recipient = "bb" * 20
        burn_amount = 20
        user.nbpburntoeth(ETH_CHAIN_ID, TOKEN, burn_amount, eth_recipient)
        self.mine(1)
        burn_epoch = self.epoch_of(node.getblockcount())
        pegouts = node.getnbppegouts(burn_epoch)
        assert_equal(len(pegouts["events"]), 1)
        ev = pegouts["events"][0]
        assert_equal(ev["eth_recipient"], eth_recipient)
        assert_equal(Decimal(str(ev["amount"])), Decimal(burn_amount))
        info = node.getnbptokeninfo(ETH_CHAIN_ID, TOKEN)
        assert_equal(Decimal(str(info["burned"])), Decimal(burn_amount))

        self.log.info("The burn's PegOutRoot is committed by a later checkpoint")
        self.mine_to_height(self.boundary_of(burn_epoch) + 1)
        rec = self.embed_checkpoint(burn_epoch)
        assert_equal(rec["pegout_root"], pegouts["pegout_root"])
        # Ethereum side would now honor the withdrawal against this root.
        self.vault_withdrawn += Decimal(burn_amount)
        self.assert_peg_solvency()

        self.log.info("Burn beyond circulating supply is rejected")
        assert_raises_rpc_error(None, "nbp-burn-exceeds-supply",
                                user.nbpburntoeth, ETH_CHAIN_ID, TOKEN, 10**6, eth_recipient)

        self.log.info("Fraud drill: challenge freezes the mint; committee rejects")
        deposit2 = "33" * 32
        amount2 = 7
        r2 = "44" * 32
        claim2 = user.nbpgetclaimcommit(r2)
        self.vault_locked += Decimal(amount2)
        bf2, agg2 = self.attest_deposit(deposit2, amount2, claim2["claim_commit"])
        user.nbpclaimdeposit(ETH_CHAIN_ID, TOKEN, deposit2, amount2, r2, bf2, agg2)
        self.mine(1)
        self.guardians[0].nbpchallenge(deposit2)
        self.mine(1)
        dep2 = node.getnbpdeposit(deposit2)
        assert_equal(dep2["status"], "challenged")
        assert_raises_rpc_error(None, "nbp-mint-frozen",
                                user.sendtokentoblsctaddress, token_id, user_token_addr, 1)
        # Committee votes to reject the (frivolous) challenge.
        res_msg = node.getnbpresolutionmsg(dep2["challenge_txid"], deposit2, 0)
        bf_res, agg_res = self.sign_quorum("resolution", res_msg)
        self.guardians[1].nbpresolve(deposit2, dep2["challenge_txid"], 0, bf_res, agg_res, 0)
        self.mine(1)
        assert_equal(node.getnbpdeposit(deposit2)["status"], "rejected")
        # Mint resumes maturing and becomes spendable.
        self.mine(MINT_MATURITY)
        user.sendtokentoblsctaddress(token_id, user_token_addr, 1)
        self.mine(1)
        self.assert_peg_solvency()

        self.log.info("Fail-safe: unresolved challenge revokes after R_max, re-mint allowed")
        deposit3 = "55" * 32
        amount3 = 5
        r3 = "66" * 32
        claim3 = user.nbpgetclaimcommit(r3)
        self.vault_locked += Decimal(amount3)
        bf3, agg3 = self.attest_deposit(deposit3, amount3, claim3["claim_commit"])
        user.nbpclaimdeposit(ETH_CHAIN_ID, TOKEN, deposit3, amount3, r3, bf3, agg3)
        self.mine(1)
        self.guardians[1].nbpchallenge(deposit3)
        self.mine(1)
        minted_before = Decimal(str(node.getnbptokeninfo(ETH_CHAIN_ID, TOKEN)["minted"]))
        self.mine(RESOLUTION_WINDOW + 1)
        assert_equal(node.getnbpdeposit(deposit3)["status"], "revoked_timeout")
        # Frozen outputs are now permanently unspendable, but the deposit id
        # can be re-attested and minted again (genuine deposit recovers).
        bf3b, agg3b = self.attest_deposit(deposit3, amount3, claim3["claim_commit"])
        user.nbpclaimdeposit(ETH_CHAIN_ID, TOKEN, deposit3, amount3, r3, bf3b, agg3b)
        self.mine(1)
        assert_equal(node.getnbpdeposit(deposit3)["status"], "minted")
        assert_equal(Decimal(str(node.getnbptokeninfo(ETH_CHAIN_ID, TOKEN)["minted"])),
                     minted_before + Decimal(amount3))
        self.mine(MINT_MATURITY)
        self.assert_peg_solvency()

        self.log.info("Dynamic finality: heavier fork below the checkpoint is not adopted")
        # node1 has been following the chain but knows nothing about pending
        # bridge state beyond consensus. Split it off and build a heavier
        # fork from before the finalized checkpoint.
        self.disconnect_nodes(0, 1)
        self.node1_connected = False
        fork_base_height = final_height - 1
        fork_base = node.getblockhash(fork_base_height)
        node1 = self.nodes[1]
        node1.invalidateblock(node.getblockhash(final_height))
        assert_equal(node1.getblockcount(), fork_base_height)
        node1_wallet_name = "miner1"
        node1.createwallet(wallet_name=node1_wallet_name, blsct=True)
        w1 = node1.get_wallet_rpc(node1_wallet_name)
        addr1 = w1.getnewaddress(label="", address_type="blsct")
        # Build a strictly longer fork on node1.
        fork_len = node.getblockcount() - fork_base_height + 5
        while fork_len > 0:
            batch = min(fork_len, 10)
            self.generatetoblsctaddress(node1, batch, addr1, sync_fun=self.no_op)
            fork_len -= batch
        assert node1.getblockcount() > node.getblockcount()
        tip_before = node.getbestblockhash()
        self.connect_nodes(0, 1)
        # Give node0 time to process node1's headers/blocks.
        import time
        deadline = time.time() + 20
        while time.time() < deadline:
            if node.getpeerinfo() and node.getbestblockhash() == tip_before:
                pass
            time.sleep(1)
        assert_equal(node.getbestblockhash(), tip_before)
        anc = node.getblockhash(final_height)
        assert_equal(anc, final_hash)
        self.disconnect_nodes(0, 1)

        self.log.info("Guardian exit + withdraw after unbonding")
        self.guardians[2].nbpexitguardian()
        self.mine(1)
        statuses = {e["status"] for e in node.getnbpguardians()}
        assert "exiting" in statuses
        assert_raises_rpc_error(None, "nbp-unbonding-immature",
                                self.guardians[2].nbpwithdrawbond, MIN_BOND)
        self.mine(50)  # U = 2*P*E + R_max
        self.guardians[2].nbpwithdrawbond(MIN_BOND)
        self.mine(1)
        statuses = [e["status"] for e in node.getnbpguardians()]
        assert "withdrawn" in statuses

        self.log.info("Final solvency check")
        self.assert_peg_solvency()


if __name__ == "__main__":
    NbpBridgeE2ETest(__file__).main()
