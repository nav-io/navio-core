#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""listunspent/listtransactions on BLSCT output-storage wallets.

Under WALLET_FLAG_BLSCT_OUTPUT_STORAGE a locally-created send is kept in
mapWallet and its outputs are mirrored into mapOutputs, so the change of a send
is known to the wallet twice. This test pins how the listing RPCs present it:

* listunspent lists every output once (unique outids), renders every BLSCT
  coin with its nv1 address, and its amounts sum to the trusted plus
  untrusted-pending balance getbalances reports -- the same dedup rule
  GetBlsctBalance() uses.
* listtransactions/listsinceblock rows that come from mapOutputs alone carry
  no containing txid. Such rows must omit `txid` rather than repeat `outid`
  under that name; any `txid` a row does carry must resolve via
  gettransaction.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

SEND_AMOUNT = Decimal("10.00000000")


def to_dec(value):
    return Decimal(str(value))


class BlsctOutputStorageRpcListingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, address, num_blocks, batch_size=10):
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            self.generatetoblsctaddress(self.nodes[0], to_generate, address)
            remaining -= to_generate

    def check_listunspent(self, wallet, label):
        balances = wallet.getbalances()["mine"]
        expected = to_dec(balances["trusted"]) + to_dec(balances["untrusted_pending"])
        unspent = wallet.listunspent(0)
        outids = [u["outid"] for u in unspent]
        self.log.info(f"[{label}] listunspent(0): {len(unspent)} entries, "
                      f"{len(set(outids))} unique, sum={sum(to_dec(u['amount']) for u in unspent)}, "
                      f"trusted+untrusted_pending={expected}")
        assert_equal(len(outids), len(set(outids)))
        for u in unspent:
            assert "address" in u, f"BLSCT coin {u['outid']} listed without an address"
        assert_equal(sum(to_dec(u["amount"]) for u in unspent), expected)

        # minconf=1 must list exactly the confirmed subset.
        confirmed = wallet.listunspent()
        assert_equal(sorted(u["outid"] for u in confirmed),
                     sorted(u["outid"] for u in unspent if u["confirmations"] >= 1))

        # The address filter must find each coin under the address it is
        # listed with, and only those coins.
        for address in {u["address"] for u in unspent}:
            filtered = wallet.listunspent(0, 9999999, [address])
            assert_equal(sorted(u["outid"] for u in filtered),
                         sorted(u["outid"] for u in unspent if u["address"] == address))

        # Amount filters are applied to the recovered BLSCT amount.
        biggest = max(to_dec(u["amount"]) for u in unspent)
        assert_equal(sorted(u["outid"] for u in wallet.listunspent(0, 9999999, [], True, {"minimumAmount": biggest})),
                     sorted(u["outid"] for u in unspent if to_dec(u["amount"]) >= biggest))
        return unspent

    def check_txids(self, wallet, rows, label):
        output_storage_rows = 0
        for e in rows:
            if "outid" in e:
                assert e.get("txid") != e["outid"], f"[{label}] row reports its outid as txid: {e}"
            if e.get("output_storage"):
                output_storage_rows += 1
            if "txid" in e:
                assert_equal(wallet.gettransaction(e["txid"])["txid"], e["txid"])
        return output_storage_rows

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="sender", blsct=True, storage_output=True)
        node.createwallet(wallet_name="receiver", blsct=True, storage_output=True)
        sender = node.get_wallet_rpc("sender")
        receiver = node.get_wallet_rpc("receiver")
        sender_addr = sender.getnewaddress(label="", address_type="blsct")
        receiver_addr = receiver.getnewaddress(label="", address_type="blsct")

        self.log.info("Fund the sender past coinbase maturity")
        self.generate_blsct_blocks(sender_addr, 201)
        start_block = node.getbestblockhash()
        self.check_listunspent(sender, "funded")

        self.log.info("Send with change; check the sender while the send is in the mempool")
        sender.sendtoblsctaddress(receiver_addr, SEND_AMOUNT)
        before = self.check_listunspent(sender, "send in mempool")
        assert any(u["confirmations"] == 0 for u in before), "unconfirmed change not listed"

        self.log.info("Confirm the send; check both wallets")
        self.generate_blsct_blocks(sender_addr, 1)
        self.check_listunspent(sender, "send confirmed")
        received = self.check_listunspent(receiver, "receive confirmed")
        assert_equal([u["address"] for u in received], [receiver_addr])
        assert_equal([to_dec(u["amount"]) for u in received], [SEND_AMOUNT])

        self.log.info("Second send, so both wallets hold more history")
        sender.sendtoblsctaddress(receiver_addr, SEND_AMOUNT)
        self.generate_blsct_blocks(sender_addr, 1)
        self.check_listunspent(sender, "second send")
        self.check_listunspent(receiver, "second receive")

        self.log.info("listtransactions/listsinceblock never report an outid as txid")
        for name, wallet in (("sender", sender), ("receiver", receiver)):
            rows = wallet.listtransactions("*", 100000, 0, True)
            since = wallet.listsinceblock(start_block)
            self.check_txids(wallet, rows, f"{name} listtransactions")
            self.check_txids(wallet, since["transactions"], f"{name} listsinceblock")

        # The receiver did not build the txs paying it: its receive rows exist
        # only in mapOutputs, and the wallet does not know their txid.
        receives = [e for e in receiver.listtransactions("*", 100000, 0, True) if e["category"] == "receive"]
        assert_equal(len(receives), 2)
        for e in receives:
            assert_equal(e["output_storage"], True)
            assert "txid" not in e, e
            # The output is still reachable by its output id.
            gt = receiver.gettransaction(e["outid"])
            assert_equal(gt["output_storage"], True)
            assert_equal(to_dec(gt["amount"]), SEND_AMOUNT)
            # The node finds the transaction holding it.
            holder = node.gettxfromoutputhash(e["outid"])
            assert holder["txid"] != e["outid"]
            assert_equal(holder["blockhash"], e["blockhash"])
        assert_greater_than(self.check_txids(sender, sender.listtransactions("*", 100000, 0, True), "sender"), 0)


if __name__ == '__main__':
    BlsctOutputStorageRpcListingTest(__file__).main()
