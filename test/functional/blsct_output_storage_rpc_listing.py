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
* A chain of sends the miner merges into one block tx under a new txid: the
  wallet matches its sends to the block tx, and the final change is listed
  once by listunspent, never as a history row of its own, and the history
  sums to the balance in listtransactions and listsinceblock.
* A send that left the mempool unmined: its CWalletTx is neither confirmed
  nor in the mempool, and the history lists it through that CWalletTx only,
  without a second, output-storage row for an output it created. Its outputs
  are not in the balance, and listunspent does not list them either.
"""

from collections import Counter
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

SEND_AMOUNT = Decimal("10.00000000")
CHAIN_LENGTH = 3


def to_dec(value):
    return Decimal(str(value))


class BlsctOutputStorageRpcListingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True
        # Plain sends: the chain below is merged by the miner, not by
        # aggregation with cover candidates.
        self.extra_args = [["-aggregatesends=0"]]

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

        # maximumCount and minimumSumAmount limit the whole listing, not each
        # of the coin lists (wallet txs, output storage) it is merged from.
        for count in sorted({1, 2, len(unspent) - 1, len(unspent), len(unspent) + 1} - {0}):
            limited = wallet.listunspent(0, 9999999, [], True, {"maximumCount": count})
            assert_equal(len(limited), min(count, len(unspent)))
            assert set(u["outid"] for u in limited) <= set(outids)
        smallest = min(to_dec(u["amount"]) for u in unspent)
        for target in (smallest, (expected / 2).quantize(Decimal("0.00000001"))):
            limited = wallet.listunspent(0, 9999999, [], True, {"minimumSumAmount": target})
            limited_sum = sum(to_dec(u["amount"]) for u in limited)
            # Listing stops at the first coin that brings the sum to the
            # target: for the smallest coin's amount, that is the first coin.
            assert limited_sum >= target, f"[{label}] minimumSumAmount {target}: listed only {limited_sum}"
            assert limited_sum - to_dec(limited[-1]["amount"]) < target, f"[{label}] minimumSumAmount {target}: listed {limited_sum} in {len(limited)} coins"

        # An unconfirmed coin's mempool ancestry is found from its outid.
        for u in unspent:
            if u["confirmations"] == 0:
                assert_greater_than(u.get("ancestorcount", 0), 0)
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

    def history_sum(self, rows):
        """Balance delta the rows describe: the amounts, plus each send's fee
        once per txid (it is repeated on every send row of a tx)."""
        fees = {e["txid"]: to_dec(e["fee"]) for e in rows if e["category"] == "send"}
        return sum(to_dec(e["amount"]) for e in rows) + sum(fees.values())

    def check_history(self, wallet, start_block, label):
        """listtransactions and listsinceblock list no output twice and sum to
        the balance."""
        balances = wallet.getbalances()["mine"]
        total = sum(to_dec(balances[k]) for k in ("trusted", "untrusted_pending", "immature"))
        rows = wallet.listtransactions("*", 100000, 0, True)
        since = wallet.listsinceblock(start_block)["transactions"]
        for name, listed in (("listtransactions", rows), ("listsinceblock", since)):
            keys = Counter((e.get("txid"), e.get("outid"), e.get("vout"), e["category"]) for e in listed)
            dupes = [k for k, n in keys.items() if n > 1]
            assert_equal(dupes, [])
            outids = Counter(e["outid"] for e in listed if "outid" in e)
            assert_equal([k for k, n in outids.items() if n > 1], [])
            self.check_txids(wallet, listed, f"{label} {name}")
        self.log.info(f"[{label}] history sum={self.history_sum(rows)} balance={total}")
        assert_equal(self.history_sum(rows), total)
        return rows, since

    def test_merged_chain(self, sender, receiver_addr):
        node = self.nodes[0]
        self.log.info(f"Chain {CHAIN_LENGTH} sends, each spending the previous one's unconfirmed change")
        start_block = node.getbestblockhash()
        txids = []
        for _ in range(CHAIN_LENGTH):
            mempool_before = set(node.getrawmempool())
            sender.sendtoblsctaddress(receiver_addr, SEND_AMOUNT)
            new = set(node.getrawmempool()) - mempool_before
            assert_equal(len(new), 1)
            txids.append(new.pop())
        unspent = self.check_listunspent(sender, "chain in mempool")
        change = [u for u in unspent if u["confirmations"] == 0]
        assert_equal(len(change), 1)
        change_outid = change[0]["outid"]

        self.log.info("Mine the chain: the miner merges it into one block tx under a new txid")
        self.generate_blsct_blocks(sender.getnewaddress(label="", address_type="blsct"), 1)
        block_txids = node.getblock(node.getbestblockhash())["tx"]
        assert_equal(len(block_txids), 2)
        assert not set(txids) & set(block_txids)
        merged_txid = block_txids[1]
        assert_equal(node.gettxfromoutputhash(change_outid)["txid"], merged_txid)

        unspent = self.check_listunspent(sender, "chain merged")
        assert_equal([u["outid"] for u in unspent if u["outid"] == change_outid], [change_outid])
        assert_greater_than([u for u in unspent if u["outid"] == change_outid][0]["confirmations"], 0)
        rows, since = self.check_history(sender, start_block, "chain merged")
        # The change nets into the send rows; it is never a row of its own.
        for listed in (rows, since):
            assert_equal([e for e in listed if e.get("outid") == change_outid], [])
        sends = [e for e in rows if e["category"] == "send" and e["txid"] in txids]
        assert_equal(sorted(e["txid"] for e in sends), sorted(txids))
        assert all(e["confirmations"] > 0 for e in sends)

    def test_send_out_of_mempool(self, sender):
        node = self.nodes[0]
        self.log.info("A self-send that leaves the mempool unmined")
        start_block = node.getbestblockhash()
        self_addr = sender.getnewaddress(label="", address_type="blsct")
        sender.sendtoblsctaddress(self_addr, SEND_AMOUNT)
        self.check_history(sender, start_block, "self-send in mempool")
        # Drop the mempool and keep the wallet from resubmitting the send.
        self.restart_node(0, extra_args=["-aggregatesends=0", "-persistmempool=0", "-walletbroadcast=0"])
        node = self.nodes[0]
        node.loadwallet("sender")
        sender = node.get_wallet_rpc("sender")
        assert_equal(node.getrawmempool(), [])
        rows = sender.listtransactions("*", 100000, 0, True)
        unconfirmed = [e for e in rows if e["confirmations"] == 0]
        self.log.info(f"rows of the send out of the mempool: {[(e['category'], e['amount'], e.get('output_storage', False)) for e in unconfirmed]}")
        # Listed once, through its CWalletTx: a send row and a receive row for
        # the output paid to the wallet's own address.
        assert_equal(Counter(e["category"] for e in unconfirmed), Counter({"send": 1, "receive": 1}))
        assert not any(e.get("output_storage") for e in unconfirmed)
        self.check_txids(sender, rows, "send out of mempool")
        since = sender.listsinceblock(start_block)["transactions"]
        assert_equal(Counter(e["category"] for e in since if e["confirmations"] == 0), Counter({"send": 1, "receive": 1}))
        # Its outputs are no coins: neither confirmed nor in the mempool, and
        # not in the balance.
        assert_equal([u for u in sender.listunspent(0) if u["confirmations"] == 0], [])
        self.check_listunspent(sender, "send out of mempool")

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
        # listpendingtransactions shares the listings' row shape: the send is
        # listed under its real txid and no row repeats an outid as txid.
        pending = sender.listpendingtransactions("*", 100000, 0, True)
        assert_greater_than(len(pending), 0)
        self.check_txids(sender, pending, "sender listpendingtransactions")
        assert all("txid" in e for e in pending if not e.get("output_storage")), pending
        self.check_txids(receiver, receiver.listpendingtransactions("*", 100000, 0, True), "receiver listpendingtransactions")

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

        self.log.info("listsinceblock's removed rows name the detached tx")
        # The removed array is filled from a block read, so its output-storage
        # rows know their containing tx and report it as txid.
        detached = node.getbestblockhash()
        block_txids = set(node.getblock(detached)["tx"])
        node.invalidateblock(detached)
        removed = receiver.listsinceblock(detached)["removed"]
        storage_rows = [e for e in removed if e.get("output_storage")]
        assert_greater_than(len(storage_rows), 0)
        for e in storage_rows:
            assert e["txid"] in block_txids, e
            assert e["txid"] != e["outid"], e
        node.reconsiderblock(detached)
        assert_equal(node.getbestblockhash(), detached)

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

        self.test_merged_chain(sender, receiver_addr)
        self.test_send_out_of_mempool(sender)


if __name__ == '__main__':
    BlsctOutputStorageRpcListingTest(__file__).main()
