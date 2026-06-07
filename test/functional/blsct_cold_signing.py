#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test the BLSCT cold-signing workflow (doc/blsct-cold-signing.md).

Verifies that an ONLINE watch-only wallet (imported from an audit key, i.e. a
private view key + public spend key) can build and fund an unsigned raw
transaction, and that an OFFLINE wallet holding the real spend keys but WITHOUT
a copy of the blockchain can sign it using only the prevout data attached to the
unsigned transaction.

The offline node is intentionally left unconnected and unsynced (it only has the
genesis block) so that signing can succeed *only* by deriving the spending keys
from the data embedded in the unsigned transaction — never from a chain lookup.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class BLSCTColdSigningTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        # node 0: ONLINE  (synced, holds the watch-only audit wallet)
        # node 1: OFFLINE (no blockchain, holds the real spend keys)
        self.num_nodes = 2
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # Deliberately do NOT connect the nodes: node 1 must stay air-gapped
        # (genesis only) so it cannot look any output up on a chain.
        self.setup_nodes()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=2):
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to_generate, address, sync_fun=self.no_op)
            remaining -= to_generate

    def run_test(self):
        online = self.nodes[0]
        offline = self.nodes[1]

        # The offline node must have no usable blockchain for this test to be
        # meaningful.
        assert_equal(offline.getblockcount(), 0)

        self.log.info("Part 1 (OFFLINE): generate the spend wallet")
        create_res = offline.createwallet(wallet_name="cold_master", blsct=True)
        mnemonic = create_res["mnemonic"]
        cold_master = offline.get_wallet_rpc("cold_master")
        cold_addr = cold_master.getnewaddress(label="", address_type="blsct")
        audit_key = cold_master.getblsctauditkey()
        # Audit key = 32-byte view key (64 hex) + 48-byte public spend key (96 hex).
        assert_equal(len(audit_key), 160)
        self.log.info(f"  cold address: {cold_addr}")

        self.log.info("Part 2 (ONLINE): import the audit key as a watch-only wallet")
        online.createwallet(wallet_name="watch", blsct=True, seed=audit_key)
        watch = online.get_wallet_rpc("watch")
        wallet_info = watch.getwalletinfo()
        assert_equal(wallet_info["blsct"], True)
        # A view-key import disables private keys: the wallet can watch but never spend.
        assert_equal(wallet_info["private_keys_enabled"], False)

        # Recipient lives on the online node so we can verify receipt.
        online.createwallet(wallet_name="recipient", blsct=True)
        recipient = online.get_wallet_rpc("recipient")
        recipient_addr = recipient.getnewaddress(label="", address_type="blsct")

        self.log.info("Funding the cold address (online node mines the blocks)")
        # The watch wallet already exists, so it detects the coinbase outputs as
        # they are connected. Mine enough for a mature, spendable balance.
        self.generate_blsct_blocks(online, cold_addr, 120)

        watch_balance = watch.getblsctbalance()
        self.log.info(f"  watch-only balance: {watch_balance}")
        assert_greater_than(watch_balance, 0)

        unspent = watch.listblsctunspent()
        assert_greater_than(len(unspent), 0)
        utxo = unspent[0]
        self.log.info(f"  spending UTXO: {utxo['outid']}")

        self.log.info("Part 3 (ONLINE): build + fund the unsigned transaction")
        send_amount = 5_000_000  # navoshis
        raw_tx = watch.createblsctrawtransaction(
            [{"outid": utxo["outid"]}],
            [{"address": recipient_addr, "amount": send_amount, "memo": "cold spend"}],
        )
        funded_tx = watch.fundblsctrawtransaction(raw_tx)
        assert funded_tx != raw_tx, "funding should change the transaction"

        # The watch-only wallet cannot sign: it has no spend keys, and the
        # deferred derivation must fail on it.
        assert_raises_rpc_error(
            -4,
            "watch-only",
            watch.signblsctrawtransaction,
            funded_tx,
        )

        self.log.info("Part 4 (OFFLINE): sign without a blockchain copy")
        # Restore the same wallet from its mnemonic on the air-gapped node.
        offline.createwallet(wallet_name="cold_signer", blsct=True, mnemonic=mnemonic)
        cold_signer = offline.get_wallet_rpc("cold_signer")

        # Prove the offline signer truly has no knowledge of the output: it owns
        # nothing and has no chain.
        assert_equal(cold_signer.getblsctbalance(), 0)
        assert_equal(len(cold_signer.listblsctunspent()), 0)
        assert_equal(offline.getblockcount(), 0)

        # The unsigned tx is fully self-describing: it can even be decoded offline.
        decoded = cold_signer.decodeblsctrawtransaction(funded_tx)
        assert_greater_than(len(decoded["inputs"]), 0)
        assert_greater_than(len(decoded["outputs"]), 0)

        # Signing succeeds purely from the prevout data attached to the tx.
        signed_tx = cold_signer.signblsctrawtransaction(funded_tx)
        assert signed_tx != funded_tx, "signing should change the transaction"

        self.log.info("Part 5 (ONLINE): broadcast the signed transaction")
        recipient_before = recipient.getblsctbalance()
        txid = online.sendrawtransaction(signed_tx)
        self.log.info(f"  broadcast txid: {txid}")
        self.generate_blsct_blocks(online, cold_addr, 1)

        recipient_after = recipient.getblsctbalance()
        self.log.info(f"  recipient balance {recipient_before} -> {recipient_after}")
        assert_greater_than(recipient_after, recipient_before)
        assert_equal(recipient_after, recipient_before + Decimal(send_amount) / Decimal(1e8))

        self.log.info("BLSCT cold-signing workflow test passed")


if __name__ == '__main__':
    BLSCTColdSigningTest(__file__).main()
