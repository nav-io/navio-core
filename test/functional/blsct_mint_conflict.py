#!/usr/bin/env python3
# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Two individually-valid mints of one capped token must not halt mining.

Mempool validation checks each tx's token predicates against the chain only,
so two mints that together exceed a token's supply cap are both accepted.
Block assembly must skip the second one during package selection (and use the
space for other transactions), and once the first one confirms the second one
must be evicted from the mempool. The wallet that created the evicted mint
marks it conflicted, so the coins it spent become spendable again, and
unconflicted once the block that caused the eviction is disconnected.
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
        token_outputs = {out["hash"] for m in mints for out in node.getrawtransaction(m, True)["vout"] if out.get("tokenId") == token_id}
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
        # All three do not fit: each pair above leaves out a tx far heavier
        # than the 4 units of slack.
        max_weight = 4000 + fits + 4
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
        (mint_block,) = self.generate_blsct_blocks(node, issuer_addr, 1)
        # Each mint is 1 token against a cap of 1, so a supply of exactly 1
        # means exactly one mint was mined.
        assert_equal(node.gettoken(token_id)["currentSupply"], 1 * COIN)
        # The transfer made it in too: the skipped mint left room for it.
        node.syncwithvalidationinterfacequeue()
        assert_equal(recv.getbalance(), SEND_AMOUNT)

        self.log.info("The over-cap mint is evicted from the mempool once the first one confirms")
        assert_equal(node.getrawmempool(), [])

        self.log.info("The issuer's wallet marks the evicted mint conflicted and frees its inputs")
        issuer = node.get_wallet_rpc("issuer")
        node.syncwithvalidationinterfacequeue()
        # The mined mint is recorded under the block's aggregated txid, so
        # only the evicted one is still in the wallet under its own txid.
        conflicted = {t["txid"] for t in issuer.listtransactions("*", 1000) if t["confirmations"] < 0}
        (evicted,) = conflicted & set(mints)
        assert_equal(issuer.gettransaction(evicted)["confirmations"], -1)
        evicted_inputs = {vin["outid"] for vin in node.decoderawtransaction(issuer.gettransaction(evicted)["hex"])["vin"]}
        # listunspent lists native coins only. The issuer's wallet may have
        # funded the evicted mint with the mined one's outputs, its token
        # output included; the token balance covers that one.
        unspent = {u["outid"] for u in issuer.listunspent()}
        assert evicted_inputs - token_outputs <= unspent, "the evicted mint's inputs are still counted as spent"
        assert_equal(issuer.gettokenbalance(token_id), 1)

        self.log.info("Mining continues")
        self.generate_blsct_blocks(node, issuer_addr, 1)
        assert_equal(node.gettoken(token_id)["currentSupply"], 1 * COIN)

        self.log.info("Disconnecting the block that caused the eviction makes the mint unconflicted again")
        node.invalidateblock(mint_block)
        # A conflicted tx's depth is derived from heights, so right after the
        # invalidation it reads 0 either way. Mine past the old height before
        # checking it.
        self.generate_blsct_blocks(node, issuer_addr, 2)
        node.syncwithvalidationinterfacequeue()
        assert_equal(issuer.gettransaction(evicted)["confirmations"], 0)
        # Unconfirmed and out of the mempool, so it can be abandoned.
        assert evicted not in node.getrawmempool()
        issuer.abandontransaction(evicted)

        self.test_multi_block_connect(node, issuer, issuer_addr)
        self.test_descendant_with_own_token(node, issuer_addr)
        self.test_reorg_undoes_create(node, issuer, issuer_addr)

    def test_multi_block_connect(self, node, issuer, issuer_addr):
        self.log.info("Blocks connecting in one step: the conflict goes to the block that touched the token")
        self.restart_node(0)
        node.loadwallet("issuer")
        issuer = node.get_wallet_rpc("issuer")
        token_id = issuer.createtoken({"name": "step"}, 1)["tokenId"]
        self.generate_blsct_blocks(node, issuer_addr, 1)
        assert_equal(node.getrawmempool(), [])

        mints = [self.submit(node, issuer.minttoken, token_id, issuer_addr, 1) for _ in range(2)]
        evicted = mints[1]
        # Blocks connect in one step when a reorg switches to a branch that
        # only overtakes the old one with its last block. Build branch X (one
        # block) and branch A-B on the same parent: A carries neither mint, B
        # the first one.
        for txid in mints:
            node.prioritisetransaction(txid=txid, fee_delta=-COIN)
        (block_x,) = self.generate_blsct_blocks(node, issuer_addr, 1)
        node.invalidateblock(block_x)
        (block_a,) = self.generate_blsct_blocks(node, issuer_addr, 1)
        assert set(mints) <= set(node.getrawmempool())
        node.prioritisetransaction(txid=mints[0], fee_delta=2 * COIN)
        (block_b,) = self.generate_blsct_blocks(node, issuer_addr, 1)
        assert_equal(node.gettoken(token_id)["currentSupply"], 1 * COIN)
        assert evicted not in node.getrawmempool()

        self.log.info("Reorg from X to A-B with the second mint back in the mempool")
        node.reconsiderblock(block_x)
        assert_equal(node.getbestblockhash(), block_b)
        node.invalidateblock(block_a)
        assert_equal(node.getbestblockhash(), block_x)
        node.syncwithvalidationinterfacequeue()
        node.prioritisetransaction(txid=evicted, fee_delta=COIN)
        node.sendrawtransaction(issuer.gettransaction(evicted)["hex"])
        # A and B connect in one step: the mint's eviction while B connects is
        # reported to the wallet before either block is.
        node.reconsiderblock(block_a)
        assert_equal(node.getbestblockhash(), block_b)
        assert evicted not in node.getrawmempool()
        node.syncwithvalidationinterfacequeue()
        # Conflicted with B, the tip, not with A.
        assert_equal(issuer.gettransaction(evicted)["confirmations"], -1)

        self.log.info("Dropping B but keeping A makes the mint valid again")
        # Keep the chain on A once B is gone.
        node.invalidateblock(block_x)
        node.invalidateblock(block_b)
        assert_equal(node.getbestblockhash(), block_a)
        self.generate_blsct_blocks(node, issuer_addr, 1)
        node.syncwithvalidationinterfacequeue()
        assert_equal(issuer.gettransaction(evicted)["confirmations"], 0)
        assert evicted not in node.getrawmempool()
        issuer.abandontransaction(evicted)

    def test_descendant_with_own_token(self, node, issuer_addr):
        self.log.info("A descendant minting another token follows its parent's conflict")
        issuer = node.get_wallet_rpc("issuer")
        self.generate_blsct_blocks(node, issuer_addr, 1)
        token_t = issuer.createtoken({"name": "parent"}, 1)["tokenId"]
        self.generate_blsct_blocks(node, issuer_addr, 1)
        token_u = issuer.createtoken({"name": "child"}, 1000)["tokenId"]
        self.generate_blsct_blocks(node, issuer_addr, 1)
        assert_equal(node.getrawmempool(), [])

        # first: mints T, mined in B. parent: mints T, evicted by B. other:
        # mints U, mined in A. child: mints U, spends parent's change. Lock
        # coins so that only child spends an unconfirmed output.
        def mint_from(token_id, allowed=lambda u: u["confirmations"] > 0):
            locked = [{"outid": u["outid"]} for u in issuer.listunspent(0) if not allowed(u)]
            if locked:
                issuer.lockunspent(False, locked)
            txid = self.submit(node, issuer.minttoken, token_id, issuer_addr, 1)
            if locked:
                issuer.lockunspent(True, locked)
            return txid
        first = mint_from(token_t)
        parent = mint_from(token_t)
        other = mint_from(token_u)
        parent_outs = {out["hash"] for out in node.getrawtransaction(parent, True)["vout"]}
        child = mint_from(token_u, lambda u: u["outid"] in parent_outs)
        for txid in (first, parent, other):
            assert_equal(node.getmempoolentry(txid)["depends"], [])
        assert_equal(node.getmempoolentry(child)["depends"], [parent])

        txs = [first, parent, other, child]
        for txid in txs:
            node.prioritisetransaction(txid=txid, fee_delta=-COIN)
        (block_x,) = self.generate_blsct_blocks(node, issuer_addr, 1)
        node.invalidateblock(block_x)
        node.prioritisetransaction(txid=other, fee_delta=2 * COIN)
        (block_a,) = self.generate_blsct_blocks(node, issuer_addr, 1)
        assert_equal(node.gettoken(token_u)["currentSupply"], 1 * COIN)
        node.prioritisetransaction(txid=first, fee_delta=2 * COIN)
        (block_b,) = self.generate_blsct_blocks(node, issuer_addr, 1)
        assert_equal(node.gettoken(token_t)["currentSupply"], 1 * COIN)
        assert not {parent, child} & set(node.getrawmempool())

        self.log.info("Reorg from X to A-B with parent and child back in the mempool")
        node.reconsiderblock(block_x)
        node.invalidateblock(block_a)
        assert_equal(node.getbestblockhash(), block_x)
        node.syncwithvalidationinterfacequeue()
        for txid in (parent, child):
            node.prioritisetransaction(txid=txid, fee_delta=COIN)
            node.sendrawtransaction(issuer.gettransaction(txid)["hex"])
        # B evicts parent, and child with it. A touched U, child's token,
        # but child must end up conflicted with B like its parent.
        node.reconsiderblock(block_a)
        assert_equal(node.getbestblockhash(), block_b)
        assert not {parent, child} & set(node.getrawmempool())
        node.syncwithvalidationinterfacequeue()
        assert_equal(issuer.gettransaction(parent)["confirmations"], -1)
        assert_equal(issuer.gettransaction(child)["confirmations"], -1)

        self.log.info("Dropping B but keeping A frees both")
        node.invalidateblock(block_x)
        node.invalidateblock(block_b)
        assert_equal(node.getbestblockhash(), block_a)
        self.generate_blsct_blocks(node, issuer_addr, 1)
        node.syncwithvalidationinterfacequeue()
        for txid in (parent, child):
            assert_equal(issuer.gettransaction(txid)["confirmations"], 0)
            assert txid not in node.getrawmempool()
        issuer.abandontransaction(parent)

    def test_reorg_undoes_create(self, node, issuer, issuer_addr):
        self.log.info("A mint whose token's creation a reorg undid is evicted")
        issuer = node.get_wallet_rpc("issuer")
        self.generate_blsct_blocks(node, issuer_addr, 1)
        token_id = issuer.createtoken({"name": "reorged"}, 1)["tokenId"]
        (create_block,) = self.generate_blsct_blocks(node, issuer_addr, 1)
        mint = self.submit(node, issuer.minttoken, token_id, issuer_addr, 1)
        node.invalidateblock(create_block)
        assert mint not in node.getrawmempool()


if __name__ == '__main__':
    BlsctMintConflictTest(__file__).main()
