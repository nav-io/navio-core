#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end test of the aggregation candidate producer.

broadcastcandidate builds a fee-0 self-spend cover candidate from the wallet's
own coin (no fee output) and floods it as a CANDIDATE_TX. This exercises the
full wallet build -> BuildCandidate -> encrypt -> transport send path. The
candidate is only valid inside a CombineHalves aggregate, so it is NOT expected
to be accepted to the mempool on its own; the test only asserts the producer
builds and broadcasts a well-formed candidate.
"""

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework


class P2PMsgCandidateTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = "blsctregtest"
        self.setup_clean_chain = True
        self.extra_args = [["-p2pmsg=1", "-p2pmsgpowbits=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=4):
        remaining = num_blocks
        while remaining > 0:
            to = min(batch_size, remaining)
            self.generatetoblsctaddress(node, to, address)
            remaining -= to

    def run_test(self):
        n = self.nodes[0]
        n.createwallet(wallet_name="w0", blsct=True, storage_output=True)
        w = n.get_wallet_rpc("w0")
        miner = w.getnewaddress(label="", address_type="blsct")

        self.generate_blsct_blocks(n, miner, 110)
        assert Decimal(str(w.getbalances()["mine"]["trusted"])) > 0

        # Producer builds and broadcasts a fee-0 cover candidate.
        res = w.broadcastcandidate()
        assert "candidate_txid" in res, res
        self.log.info("broadcastcandidate txid=%s" % res["candidate_txid"])

        # The candidate pays no fee, so it must NOT stand alone in the mempool:
        # it is only valid merged into an aggregate. Confirm it did not enter.
        assert res["candidate_txid"] not in n.getrawmempool(), \
            "fee-0 candidate must not be accepted standalone"

        # A second call builds a distinct candidate (fresh coin/self-spend).
        res2 = w.broadcastcandidate()
        assert res2["candidate_txid"] != res["candidate_txid"], "candidate not distinct"
        self.log.info("candidate producer OK")


if __name__ == "__main__":
    P2PMsgCandidateTest(__file__).main()
