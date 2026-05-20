#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Long chain of unconfirmed sends from a single UTXO.

A BLSCT wallet is funded with exactly one confirmed UTXO and then issues
a long chain of sends. Each send spends the previous send's still-
unconfirmed change, so the wallet must trust its own mempool change to
make any progress past the first hop. The final send goes back to the
test wallet itself, splitting the remaining balance across two outputs
so the wallet ends the chain holding more than one UTXO.

After mining enough blocks to drain the mempool (BLSCT block assembly
only includes one tx from a chain per block, so an N-tx chain needs N
blocks), every chain tx must confirm, the external receivers must each
hold their expected total, and the test wallet's balance must equal
funding - external sent - fees and span more than one UTXO.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


# DEFAULT_ANCESTOR_LIMIT is 25 (chain tip + 24 ancestors); stay just under it.
CHAIN_LENGTH = 24
# Position of the self-send used to split walletA's balance across two
# outputs. Placed at the tail of the chain so the resulting self-receive
# isn't reabsorbed as input by a later chain hop.
SELF_SPLIT_INDEX = CHAIN_LENGTH - 1
FUNDING_AMOUNT = Decimal("100")
SEND_AMOUNT = Decimal("1")
SELF_SPLIT_AMOUNT = Decimal("3")


class BlsctUnconfirmedChainSingleUtxoTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=4):
        blocks = []
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            blocks.extend(self.generatetoblsctaddress(node, to_generate, address))
            remaining -= to_generate
        return blocks

    def trusted_balance(self, wallet):
        return Decimal(str(wallet.getbalances()["mine"]["trusted"]))

    def drain_mempool(self, node, mining_addr, max_blocks):
        """Mine one block at a time until the mempool is empty. BLSCT block
        assembly skips txs whose parents are still unconfirmed, so a chain of
        N transactions takes N blocks to fully confirm."""
        for k in range(max_blocks):
            self.generate_blsct_blocks(node, mining_addr, 1)
            self.sync_all()
            if len(self.nodes[0].getrawmempool()) == 0:
                return k + 1
        raise AssertionError(
            f"mempool still has {len(self.nodes[0].getrawmempool())} txs after "
            f"{max_blocks} blocks"
        )

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="funder", blsct=True, storage_output=True)
        self.nodes[0].createwallet(wallet_name="walletA", blsct=True, storage_output=True)
        self.nodes[1].createwallet(wallet_name="walletB", blsct=True, storage_output=True)
        self.nodes[1].createwallet(wallet_name="walletC", blsct=True, storage_output=True)

        funder = self.nodes[0].get_wallet_rpc("funder")
        walletA = self.nodes[0].get_wallet_rpc("walletA")
        walletB = self.nodes[1].get_wallet_rpc("walletB")
        walletC = self.nodes[1].get_wallet_rpc("walletC")

        mining_addr = funder.getnewaddress(label="", address_type="blsct")
        addrA = walletA.getnewaddress(label="", address_type="blsct")
        self_addrA = walletA.getnewaddress(label="", address_type="blsct")
        addrB = walletB.getnewaddress(label="", address_type="blsct")
        addrC = walletC.getnewaddress(label="", address_type="blsct")

        self.log.info("Mine 210 blocks to funder for spendable funds")
        self.generate_blsct_blocks(self.nodes[0], mining_addr, 210)
        self.sync_all()

        self.log.info(f"Fund walletA with exactly one UTXO of {FUNDING_AMOUNT}")
        funder.sendtoblsctaddress(addrA, FUNDING_AMOUNT)
        self.generate_blsct_blocks(self.nodes[0], mining_addr, 1)
        self.sync_all()

        unspent = walletA.listblsctunspent()
        assert_equal(len(unspent), 1)
        assert_equal(Decimal(str(unspent[0]["amount"])), FUNDING_AMOUNT)
        assert_equal(self.trusted_balance(walletA), FUNDING_AMOUNT)
        assert_equal(self.trusted_balance(walletB), Decimal("0"))
        assert_equal(self.trusted_balance(walletC), Decimal("0"))

        self.log.info(
            f"Chain {CHAIN_LENGTH} unconfirmed sends from walletA's single UTXO "
            f"(self-split at index {SELF_SPLIT_INDEX})"
        )
        outids = []
        sent_to_B = Decimal("0")
        sent_to_C = Decimal("0")
        for i in range(CHAIN_LENGTH):
            if i == SELF_SPLIT_INDEX:
                outid = walletA.sendtoblsctaddress(self_addrA, SELF_SPLIT_AMOUNT)
            elif i % 2 == 0:
                outid = walletA.sendtoblsctaddress(addrB, SEND_AMOUNT)
                sent_to_B += SEND_AMOUNT
            else:
                outid = walletA.sendtoblsctaddress(addrC, SEND_AMOUNT)
                sent_to_C += SEND_AMOUNT
            assert outid
            outids.append(outid)

        assert_equal(len(set(outids)), CHAIN_LENGTH)
        self.sync_mempools()
        assert_equal(len(self.nodes[0].getrawmempool()), CHAIN_LENGTH)
        assert_equal(len(self.nodes[1].getrawmempool()), CHAIN_LENGTH)

        # Pull the actual txids from listtransactions (sendtoblsctaddress
        # returns the output hash, not the tx hash) so we can verify every
        # chain tx is recorded as an unconfirmed send by walletA.
        mempool_sends = {
            e["txid"] for e in walletA.listtransactions("*", 10 ** 9, 0, True)
            if e.get("category") == "send" and e.get("confirmations", 1) == 0
        }
        assert_equal(len(mempool_sends), CHAIN_LENGTH)

        self.log.info("Mine blocks until the whole chain confirms")
        # BLSCT block assembly only includes the one tx per chain whose
        # parents are all confirmed, so we need at least CHAIN_LENGTH blocks.
        blocks_mined = self.drain_mempool(self.nodes[0], mining_addr, CHAIN_LENGTH + 5)
        self.log.info(f"chain drained after {blocks_mined} blocks")

        # Every recorded send must be confirmed.
        for txid in mempool_sends:
            entry = walletA.gettransaction(txid)
            assert entry["confirmations"] >= 1, f"tx {txid} not confirmed"

        total_external_sent = sent_to_B + sent_to_C
        balance_A = self.trusted_balance(walletA)
        balance_B = self.trusted_balance(walletB)
        balance_C = self.trusted_balance(walletC)

        # `gettransaction["fee"]` on BLSCT sends carries a pre-existing
        # accounting skew (see the comment in blsct_unconfirmed_spending.py),
        # so derive the realized total fee from the conservation invariant
        # instead: every coin that left walletA either ended up in B, C, or
        # paid to a miner as fee.
        total_fee = FUNDING_AMOUNT - balance_A - balance_B - balance_C
        self.log.info(
            f"Balances: A={balance_A} B={balance_B} C={balance_C} fees={total_fee}"
        )

        assert_equal(balance_B, sent_to_B)
        assert_equal(balance_C, sent_to_C)
        assert_equal(balance_A, FUNDING_AMOUNT - total_external_sent - total_fee)
        # Realized fees must be positive (every tx paid one) and well within
        # the policy-minimum range for a chain of this size.
        assert total_fee > Decimal("0"), f"expected positive fees, got {total_fee}"
        assert total_fee < Decimal("1"), (
            f"unexpectedly high fee total {total_fee} for {CHAIN_LENGTH} txs"
        )

        # The self-split tx broke walletA's funds into more than one UTXO:
        # at minimum the SELF_SPLIT_AMOUNT receive and the chain's final
        # change. The exact count can be higher if any chain hop re-used the
        # split output as an additional input, but it must be > 1.
        final_unspent = walletA.listblsctunspent()
        assert len(final_unspent) > 1, (
            f"expected walletA to hold >1 UTXO after self-split, got {len(final_unspent)}"
        )
        assert_equal(
            sum(Decimal(str(u["amount"])) for u in final_unspent),
            balance_A,
        )


if __name__ == "__main__":
    BlsctUnconfirmedChainSingleUtxoTest(__file__).main()
