#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A mint must not spend the issuer's existing balance of the token it mints.

Minting needs native coins for the fee only: the minted amount comes from the
mint predicate, not from inputs. The wallet used to gather the issuer's coins
of the minted token as inputs too, so every mint after the first swept the
tokens already held into itself and returned them as token change. While such
a mint is unconfirmed those tokens move with it; if it is never mined (dropped
from the mempool on a restart, or evicted because a sibling mint filled the
token's supply cap) the wallet still counts them as spent by it, and
gettokenbalance reports 0 although the earlier mint is confirmed.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

COIN = 100_000_000


class BlsctTokenMintInputsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks, batch_size=2):
        while num_blocks > 0:
            n = min(batch_size, num_blocks)
            self.generatetoblsctaddress(node, n, address)
            num_blocks -= n

    def run_test(self):
        node = self.nodes[0]
        # Both wallet modes: the test framework defaults to storage_output=False,
        # createwallet itself to True.
        wallets = {}
        for name, storage in [("plain", False), ("storage", True)]:
            node.createwallet(wallet_name=name, blsct=True, storage_output=storage)
            wallet = node.get_wallet_rpc(name)
            addr = wallet.getnewaddress(label="", address_type="blsct")
            self.generate_blsct_blocks(node, addr, 102)
            wallets[name] = (wallet, addr)

        token_ids = {}
        for name, (wallet, addr) in wallets.items():
            self.log.info(f"{name}: minting 1 token and confirming it")
            token_id = wallet.createtoken({"name": name}, 1000)["tokenId"]
            token_ids[name] = token_id
            self.generate_blsct_blocks(node, addr, 1)
            wallet.minttoken(token_id, addr, 1)
            self.generate_blsct_blocks(node, addr, 1)
            assert_equal(wallet.gettokenbalance(token_id), 1)

        for name, (wallet, addr) in wallets.items():
            self.log.info(f"{name}: a second mint does not spend the token already held")
            token_id = token_ids[name]
            held = self.token_outputs(node, token_id)
            assert_equal(len(held), 1)
            before = set(node.getrawmempool())
            wallet.minttoken(token_id, addr, 2)
            (mint,) = set(node.getrawmempool()) - before
            spent = {vin["outid"] for vin in node.getrawtransaction(mint, True)["vin"]}
            assert not spent & held, "the mint spends the issuer's existing token output"

        self.log.info("The held token stays in the balance when the second mint is dropped unmined")
        # Without a persisted mempool the second mints are gone after the
        # restart; with wallet broadcast off they are not resubmitted when the
        # wallets load.
        self.restart_node(0, extra_args=["-persistmempool=0", "-walletbroadcast=0"])
        assert_equal(node.getrawmempool(), [])
        for name, token_id in token_ids.items():
            node.loadwallet(name)
            wallet = node.get_wallet_rpc(name)
            assert_equal(node.gettoken(token_id)["currentSupply"], 1 * COIN)
            assert_equal(wallet.gettokenbalance(token_id), 1)

    def token_outputs(self, node, token_id):
        """Hashes of the outputs of `token_id` in the active chain's last 10 blocks."""
        ret = set()
        tip = node.getblockcount()
        for height in range(tip - 9, tip + 1):
            for tx in node.getblock(node.getblockhash(height), 2)["tx"]:
                ret |= {out["hash"] for out in tx["vout"] if out.get("tokenId") == token_id}
        return ret


if __name__ == '__main__':
    BlsctTokenMintInputsTest(__file__).main()
