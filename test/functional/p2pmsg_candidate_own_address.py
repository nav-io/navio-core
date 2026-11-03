#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A served cover candidate pays the subaddress of the coin it spends.

A producer wallet on node1 holds one coin, received on a labelled address, and
serves it to node0 as a cover candidate. A send on node0 merges the cover,
pays the producer's same address, and is mined. Afterwards:

- the producer's coin is still on its address, not moved to the change
  account for having been used as cover;
- its history shows the coin it was paid and the new payment, and no send or
  receive for the cover, which a receive address does not make change by
  account. The payment shares the cover's address and transaction, so it
  must not be taken for the cover coming back.

Run for an output-storage producer and for a full-transaction one.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

PULL_ARGS = ["-p2pmsg=1", "-p2pmsgpowbits=1", "-candidatepullinterval=2", "-servecandidates=0"]


class P2PMsgCandidateOwnAddressTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        # Node1 sends plain transfers to fund the wallets.
        self.extra_args = [PULL_ARGS, PULL_ARGS + ["-aggregatesends=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def mine(self, node, address, num_blocks, batch_size=4):
        remaining = num_blocks
        while remaining > 0:
            to = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to, address)
            remaining -= to
        self.sync_blocks()

    def addr(self, wallet, label=""):
        return wallet.getnewaddress(label=label, address_type="blsct")

    def run_test(self):
        n1 = self.nodes[1]
        n1.createwallet(wallet_name="funder", blsct=True, storage_output=True)
        self.funder = n1.get_wallet_rpc("funder")
        self.funder_addr = self.addr(self.funder)
        self.mine(n1, self.funder_addr, 110)
        for storage in (True, False):
            self.check_producer(storage)

    def check_producer(self, storage):
        n0, n1 = self.nodes
        suffix = "storage" if storage else "full"
        self.log.info(f"Producer wallet with storage_output={storage}")
        n0.createwallet(wallet_name=f"sender_{suffix}", blsct=True, storage_output=True)
        n1.createwallet(wallet_name=f"producer_{suffix}", blsct=True, storage_output=storage)
        sender = n0.get_wallet_rpc(f"sender_{suffix}")
        producer = n1.get_wallet_rpc(f"producer_{suffix}")

        self.log.info("Pay the producer one coin on a labelled address, and fund the sender")
        # Move the producer to a later receive subaddress, so a regression
        # that pays the cover to the default address is caught too.
        self.addr(producer)
        savings = self.addr(producer, "savings")
        # Both are transfers, so the sender's send blends with this cover.
        self.funder.sendtoblsctaddress(savings, 10)
        self.funder.sendtoblsctaddress(self.addr(sender), 10)
        self.wait_until(lambda: len(n1.getrawmempool()) == 2, timeout=60)
        self.mine(n1, self.funder_addr, 1)
        self.wait_until(lambda: len(sender.listblsctunspent()) == 1, timeout=60)
        assert_equal(Decimal(str(producer.getbalanceforaddress(savings)["mine"]["trusted"])), Decimal("10"))

        self.log.info("Serve the producer's coin to node0 as a cover candidate")
        keys = []

        def got_one():
            keys.extend(n1.listpendingcandidaterequests())
            return len(keys) > 0

        self.wait_until(got_one, timeout=120)
        reply = producer.replycandidate(keys[0])
        assert_equal(len(reply["inputs"]), 1)
        cover_input = reply["inputs"][0]
        self.wait_until(lambda: n0.getaggregationhint()["available"] == 1, timeout=120)

        self.log.info("A send on node0 merges the cover, pays the same address, and is mined")
        sender.sendtoblsctaddress(savings, 1)
        self.wait_until(lambda: len(n0.getrawmempool()) == 1, timeout=60)
        tx = n0.getrawtransaction(n0.getrawmempool()[0], True)
        assert cover_input in {vin["outid"] for vin in tx["vin"] if "outid" in vin}, "the cover was not merged"
        self.mine(n0, self.funder_addr, 1)
        assert_equal(n0.getrawmempool(), [])

        self.log.info("The producer's coin is still on its labelled address")
        self.wait_until(lambda: Decimal(str(producer.getblsctbalance())) == Decimal("11"), timeout=60)
        assert_equal(Decimal(str(producer.getbalanceforaddress(savings)["mine"]["trusted"])), Decimal("11"))

        self.log.info("The history shows the two payments and nothing for the cover")
        entries = producer.listtransactions("*", 1000)
        assert not [e for e in entries if e.get("memo") == "candidate"], entries
        assert not [e for e in entries if e["category"] == "send"], entries
        received = [e for e in entries if e["category"] == "receive"]
        assert_equal(sorted(Decimal(str(e["amount"])) for e in received), [Decimal("1"), Decimal("10")])
        assert_equal({e["label"] for e in received}, {"savings"})


if __name__ == "__main__":
    P2PMsgCandidateOwnAddressTest(__file__).main()
