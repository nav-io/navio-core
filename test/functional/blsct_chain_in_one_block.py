#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Chained BLSCT sends must all confirm in the same block.

Wallet A funds itself with one UTXO, then issues a chain of N dependent
BLSCT sends where each child spends the prior send's unconfirmed change.
A second node receives the chain via P2P, then mines a single block.
That one block must contain — and confirm — every tx in the chain.

This exercises the path where the staking node was not the source of
the txs: it learned them by relay, then aggregated the whole chain into
a single block.vtx[1] aggregate tx, whose vin set references vouts
inside its own vout list. Block validation must pre-resolve those
internal sibling vouts.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


CHAIN_LENGTH = 8
FUNDING_AMOUNT = Decimal("100")
SEND_AMOUNT = Decimal("1")


class BlsctChainInOneBlockTest(BitcoinTestFramework):
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

    def total_balance(self, wallet):
        m = wallet.getbalances()["mine"]
        return (Decimal(str(m["trusted"]))
                + Decimal(str(m["untrusted_pending"]))
                + Decimal(str(m["immature"]))
                + Decimal(str(m.get("staked_commitment_balance", 0)))
                + Decimal(str(m.get("pending_staked_commitment_balance", 0))))

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="funder", blsct=True, storage_output=True)
        self.nodes[0].createwallet(wallet_name="walletA", blsct=True, storage_output=True)
        self.nodes[1].createwallet(wallet_name="walletB", blsct=True, storage_output=True)

        funder = self.nodes[0].get_wallet_rpc("funder")
        walletA = self.nodes[0].get_wallet_rpc("walletA")
        walletB = self.nodes[1].get_wallet_rpc("walletB")

        # node[1] mines the test block — it learns the chain via P2P, never
        # builds it locally — so the block-assembly path under test is the
        # one a remote staker would take. Mining reward goes to a separate
        # wallet to keep walletB's balance equal to the chain receipts only.
        self.nodes[1].createwallet(wallet_name="miner1", blsct=True, storage_output=True)
        miner1 = self.nodes[1].get_wallet_rpc("miner1")
        mining_addr_1 = miner1.getnewaddress(label="", address_type="blsct")
        funder_addr = funder.getnewaddress(label="", address_type="blsct")
        addrA = walletA.getnewaddress(label="", address_type="blsct")
        addrB = walletB.getnewaddress(label="", address_type="blsct")

        self.log.info("Mine 210 blocks to funder for spendable funds")
        self.generate_blsct_blocks(self.nodes[0], funder_addr, 210)
        self.sync_all()

        self.log.info(f"Fund walletA with one UTXO of {FUNDING_AMOUNT}")
        funder.sendtoblsctaddress(addrA, FUNDING_AMOUNT)
        self.generate_blsct_blocks(self.nodes[0], funder_addr, 1)
        self.sync_all()
        assert_equal(len(walletA.listblsctunspent()), 1)
        assert_equal(self.trusted_balance(walletA), FUNDING_AMOUNT)

        self.log.info(f"Submit chain of {CHAIN_LENGTH} dependent sends from walletA")
        chain_txids = []
        for i in range(CHAIN_LENGTH):
            outid = walletA.sendtoblsctaddress(addrB, SEND_AMOUNT)
            assert outid
            chain_txids.append(outid)

        self.sync_mempools()
        # Both nodes must see the full chain.
        assert_equal(len(self.nodes[0].getrawmempool()), CHAIN_LENGTH)
        assert_equal(len(self.nodes[1].getrawmempool()), CHAIN_LENGTH)

        self.log.info("Mine ONE block on node[1] — must confirm the whole chain")
        pre_height = self.nodes[1].getblockcount()
        block_hashes = self.generate_blsct_blocks(self.nodes[1], mining_addr_1, 1)
        self.sync_all()
        assert_equal(len(block_hashes), 1)
        assert_equal(self.nodes[1].getblockcount(), pre_height + 1)

        # The one block must have drained the mempool.
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        assert_equal(len(self.nodes[1].getrawmempool()), 0)

        # The block has 2 entries (BLSCT format: coinbase + aggregated tx
        # combining the entire chain). Original per-tx txids do not appear
        # on chain — they're merged into the aggregate's single txid, so
        # we cannot look up chain txs by their original txid.
        block = self.nodes[0].getblock(block_hashes[0])
        assert_equal(len(block["tx"]), 2)

        # The aggregate must carry all chain inputs (1 per chain hop) and
        # outputs (1 recipient + 1 change per hop, plus the merged fee
        # output added by AggregateTransactions).
        agg = self.nodes[0].getrawtransaction(block["tx"][1], True, block_hashes[0])
        assert_equal(len(agg["vin"]), CHAIN_LENGTH)
        # Per hop: recipient + change vout. Fee outputs from each hop
        # collapse into a single aggregate fee output.
        assert_equal(len(agg["vout"]), 2 * CHAIN_LENGTH + 1)

        # walletB receives SEND_AMOUNT * CHAIN_LENGTH: every chain hop paid
        # SEND_AMOUNT. Receiver-side wallet tracks the agg's outputs that
        # belong to it correctly.
        balance_B = self.total_balance(walletB)
        assert_equal(balance_B, SEND_AMOUNT * CHAIN_LENGTH)

        # Sender-side: getbalances must report the change as trusted. When
        # the chain is aggregated, the aggregate's txid does not match any
        # of walletA's locally-recorded send txs, so the wallet's CWalletTx
        # records for the chain end up TxStateInactive. The balance code in
        # GetBlsctBalance must still count the resulting change outputs via
        # mapOutputs — they are confirmed coins owned by us.
        balance_A = self.total_balance(walletA)
        a_unspent = walletA.listblsctunspent(0)
        a_owned = sum(Decimal(str(u["amount"])) for u in a_unspent)
        assert_equal(balance_A, a_owned)
        total_fee = FUNDING_AMOUNT - balance_A - balance_B
        assert total_fee > Decimal("0"), f"expected positive fees, got {total_fee}"
        assert total_fee < Decimal("1"), (
            f"unexpectedly high fee total {total_fee} for {CHAIN_LENGTH} txs"
        )

        # Every CWalletTx that walletA created for the chain must now be
        # marked confirmed. The aggregate's hash differs from the original
        # chain txids, so blockConnected reconciles via the vout-to-CWalletTx
        # reverse index.
        unconfirmed_sends = [
            e for e in walletA.listtransactions("*", 10 ** 9, 0, True)
            if e.get("category") == "send" and e.get("confirmations", 0) == 0
        ]
        assert_equal(len(unconfirmed_sends), 0)


if __name__ == "__main__":
    BlsctChainInOneBlockTest(__file__).main()
