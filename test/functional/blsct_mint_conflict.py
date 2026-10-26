#!/usr/bin/env python3
# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Two individually-valid mints of one capped token must not halt mining.

Mempool validation checks each tx's token predicates against the chain only,
so two mints that together exceed a token's supply cap are both accepted.
Block assembly must skip the second one during package selection (and use the
space for other transactions), and once the first one confirms the second one
must be evicted from the mempool.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

COIN = 100_000_000
SEND_AMOUNT = Decimal("1")


class BlsctMintConflictTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=2):
        blocks = []
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            blocks.extend(self.generatetoblsctaddress(node, to_generate, address))
            remaining -= to_generate
        return blocks

    def submit(self, node, fn, *args):
        """Run a wallet call that broadcasts one tx and return that tx's txid."""
        before = set(node.getrawmempool())
        fn(*args)
        new = set(node.getrawmempool()) - before
        assert_equal(len(new), 1)
        return new.pop()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="issuer", blsct=True)
        node.createwallet(wallet_name="payer", blsct=True)
        node.createwallet(wallet_name="recv", blsct=True)
        issuer = node.get_wallet_rpc("issuer")
        payer = node.get_wallet_rpc("payer")
        recv = node.get_wallet_rpc("recv")
        issuer_addr = issuer.getnewaddress(label="", address_type="blsct")
        payer_addr = payer.getnewaddress(label="", address_type="blsct")
        recv_addr = recv.getnewaddress(label="", address_type="blsct")

        self.log.info("Funding an issuer and an unrelated payer")
        self.generate_blsct_blocks(node, payer_addr, 1)
        self.generate_blsct_blocks(node, issuer_addr, 102)

        self.log.info("Creating a token with max supply 1 and confirming it")
        token_id = issuer.createtoken({"name": "conflict"}, 1)["tokenId"]
        self.generate_blsct_blocks(node, issuer_addr, 1)
        assert_equal(node.gettoken(token_id)["currentSupply"], 0)

        self.log.info("Submitting two mints of 1 (each valid against the chain) and an unrelated transfer")
        mints = [self.submit(node, issuer.minttoken, token_id, issuer_addr, 1) for _ in range(2)]
        transfer = self.submit(node, payer.sendtoblsctaddress, recv_addr, SEND_AMOUNT)
        # The issuer's wallet may fund the second mint from the first one's
        # change. Either way the second mint can only be mined after the first
        # and fails there; the payer's transfer is independent of both.
        assert_equal(node.getmempoolentry(transfer)["depends"], [])
        assert not set(node.getmempoolentry(mints[0])["depends"]) & set(mints)

        self.log.info("Restarting with a block weight that fits one mint and the transfer, but not all three")
        # With the mints prioritised, selection tries the mints first. Only
        # one of them can be mined; if the other were still added during
        # selection (and only dropped afterwards), the transfer would no
        # longer fit and the block would carry the first mint alone. Size the
        # block (after the 4000 weight units reserved for the coinbase) so
        # that either mint plus the transfer fits, and so do both mints, but
        # all three do not.
        weights = {txid: node.getmempoolentry(txid)["weight"] for txid in mints + [transfer]}
        fits = max(max(weights[m] for m in mints) + weights[transfer], sum(weights[m] for m in mints))
        max_weight = 4000 + fits + 4
        assert 4000 + sum(weights.values()) >= max_weight
        self.restart_node(0, extra_args=[f"-blockmaxweight={max_weight}"])
        self.wait_until(lambda: node.getmempoolinfo()["loaded"])
        assert_equal(set(node.getrawmempool()), set(mints + [transfer]))
        for name in ["issuer", "payer", "recv"]:
            if name not in node.listwallets():
                node.loadwallet(name)
        # The old RPC handle carries the previous run's auth cookie.
        recv = node.get_wallet_rpc("recv")
        for txid in mints:
            node.prioritisetransaction(txid=txid, fee_delta=COIN)

        self.log.info("Mining: one mint and the transfer are included, the over-cap mint is skipped")
        self.generate_blsct_blocks(node, issuer_addr, 1)
        # Each mint is 1 token against a cap of 1, so a supply of exactly 1
        # means exactly one mint was mined.
        assert_equal(node.gettoken(token_id)["currentSupply"], 1 * COIN)
        # The transfer made it in too: the skipped mint left room for it.
        node.syncwithvalidationinterfacequeue()
        assert_equal(recv.getbalance(), SEND_AMOUNT)

        self.log.info("The over-cap mint is evicted from the mempool once the first one confirms")
        assert_equal(node.getrawmempool(), [])

        self.log.info("Mining continues")
        self.generate_blsct_blocks(node, issuer_addr, 1)
        assert_equal(node.gettoken(token_id)["currentSupply"], 1 * COIN)


if __name__ == '__main__':
    BlsctMintConflictTest(__file__).main()
