#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Replicate user report: send 5 BLSCT txs of 10 NAV each, the network
packs them in one block, then getbalances returns ALL ZERO.

User getbalances after the bug:
  trusted=0 staked_commitment_balance=0 pending_staked_commitment_balance=0
  untrusted_pending=0 immature=0

Wallet flag: storage_output=True (BLSCT output-storage). The triggering
shape is several confirmed UTXOs near the per-send size so coin selection
picks one UTXO per send (no shared inputs ⇒ siblings) and the 5 sends
race into the same block as siblings.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


NUM_SENDS = 5
SEND_AMOUNT = Decimal("10")
# Each input slightly bigger than SEND_AMOUNT so coin selection picks
# exactly one per send.
UTXO_AMOUNT = Decimal("10.01")  # just over SEND + fee, tiny change
FUNDING_TOTAL = UTXO_AMOUNT * NUM_SENDS


class BlsctSameBlockMultiSendTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks):
        blocks = []
        for _ in range(num_blocks):
            blocks.extend(self.generatetoblsctaddress(node, 1, address))
        return blocks

    def balances(self, w):
        m = w.getbalances()["mine"]
        return {
            "trusted": Decimal(str(m["trusted"])),
            "pending": Decimal(str(m["untrusted_pending"])),
            "immature": Decimal(str(m["immature"])),
            "stake": Decimal(str(m.get("staked_commitment_balance", 0))),
            "pstake": Decimal(str(m.get("pending_staked_commitment_balance", 0))),
        }

    def total(self, w):
        b = self.balances(w)
        return b["trusted"] + b["pending"] + b["immature"] + b["stake"] + b["pstake"]

    def log_state(self, w, label):
        b = self.balances(w)
        unspent = w.listblsctunspent(0, 9999999)
        self.log.info(
            f"[{label}] trusted={b['trusted']} pending={b['pending']} "
            f"stake={b['stake']} utxos={len(unspent)} "
            f"sum_utxo={sum(Decimal(str(u['amount'])) for u in unspent)}"
        )

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="funder", blsct=True, storage_output=True)
        self.nodes[0].createwallet(wallet_name="sender", blsct=True, storage_output=True)
        self.nodes[1].createwallet(wallet_name="receiver", blsct=True, storage_output=True)

        funder = self.nodes[0].get_wallet_rpc("funder")
        sender = self.nodes[0].get_wallet_rpc("sender")
        receiver = self.nodes[1].get_wallet_rpc("receiver")

        miner_addr = funder.getnewaddress(label="", address_type="blsct")
        recv_addr = receiver.getnewaddress(label="", address_type="blsct")

        self.generate_blsct_blocks(self.nodes[0], miner_addr, 210)
        self.sync_all()

        # Build NUM_SENDS independent confirmed UTXOs near per-send size.
        for _ in range(NUM_SENDS):
            a = sender.getnewaddress(label="", address_type="blsct")
            funder.sendtoblsctaddress(a, UTXO_AMOUNT)
            self.generate_blsct_blocks(self.nodes[0], miner_addr, 1)
            self.sync_all()

        unspent = sender.listblsctunspent()
        assert_equal(len(unspent), NUM_SENDS)
        assert_equal(sum(Decimal(str(u["amount"])) for u in unspent), FUNDING_TOTAL)
        assert_equal(self.balances(sender)["trusted"], FUNDING_TOTAL)
        self.log_state(sender, "before sends")

        # 5 sends of 10 NAV. With UTXOs ~10.5 NAV, coin selection picks one
        # per send → 5 sibling sends.
        for i in range(NUM_SENDS):
            sender.sendtoblsctaddress(recv_addr, SEND_AMOUNT)
            self.log_state(sender, f"after send {i+1}/5 (mempool)")

        self.sync_mempools()
        assert_equal(len(self.nodes[0].getrawmempool()), NUM_SENDS)

        # Drain mempool (BLSCT block aggregation may need >1 block).
        for _ in range(NUM_SENDS + 5):
            self.generate_blsct_blocks(self.nodes[0], miner_addr, 1)
            self.sync_all()
            self.log_state(sender, "after block")
            if len(self.nodes[0].getrawmempool()) == 0:
                break

        b = self.balances(sender)
        total = self.total(sender)
        recv_total = Decimal(str(receiver.getbalances()["mine"]["trusted"]))
        self.log.info(
            f"after-block getbalances: trusted={b['trusted']} "
            f"pending={b['pending']} immature={b['immature']} "
            f"stake={b['stake']} pstake={b['pstake']} TOTAL={total} "
            f"receiver={recv_total}"
        )

        # Funds conservation: BLSCT block aggregation may pack only a
        # subset of the 5 mempool sends; the rest get conflict-evicted
        # from the mempool. That is acceptable — the user can retry them.
        # What is NOT acceptable is the sender's balance vanishing: every
        # input that did NOT make it into the block must remain spendable.
        #   sender_total + receiver = funding - fees_for_confirmed_sends
        # so sender_total ≈ funding - receiver (modulo small fees).
        expected_sender = FUNDING_TOTAL - recv_total - Decimal("0.1")
        assert total >= expected_sender, (
            f"BUG REPLICATED: sender total {total} below {expected_sender}. "
            f"Funds vanished: funding={FUNDING_TOTAL} receiver={recv_total} "
            f"sender={total}. Inputs of evicted mempool sends stuck as "
            f"m_state_spent=TxStateInMempool and never reset."
        )


if __name__ == "__main__":
    BlsctSameBlockMultiSendTest(__file__).main()
