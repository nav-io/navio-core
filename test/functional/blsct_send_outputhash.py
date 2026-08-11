#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""The outputHash returned by the BLSCT send RPCs must identify the RECIPIENT.

`TxFactoryBase::BuildTx` shuffles vout before returning (a privacy measure), so
the recipient output sits at no fixed position. Recovering it positionally --
`tx->vout[0]` -- returned the change output or the fee output roughly two sends
out of three. A fee-output handle is worse than merely wrong: when a block
confirms more than one BLSCT transaction the staker's aggregator replaces the
per-transaction fee outputs with a single merged one, so that hash never
appears on chain and `gettxfromoutputhash` can never resolve it.

Ten sends make a positional bug effectively certain to trip here.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


NUM_SENDS = 10
SEND_AMOUNT = Decimal("1")
# blsctregtest requires a minimum stake of 100 NAV.
STAKE_AMOUNT = Decimal("100")
# The send that pays its own fee out of the amount. With
# subtractfeefromamount the recipient output is built last and appended AFTER
# the change output, so it was not even at pre-shuffle vout[0].
SUBTRACT_FEE_SEND = 3


class BlsctSendOutputHashTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 2
        self.chain = "blsctregtest"
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, node, address, num_blocks):
        for _ in range(num_blocks):
            self.generatetoblsctaddress(node, 1, address)

    def run_test(self):
        self.nodes[0].createwallet(wallet_name="sender", blsct=True, storage_output=True)
        self.nodes[1].createwallet(wallet_name="receiver", blsct=True, storage_output=True)

        sender = self.nodes[0].get_wallet_rpc("sender")
        receiver = self.nodes[1].get_wallet_rpc("receiver")

        self.miner_addr = sender.getnewaddress(label="", address_type="blsct")
        self.generate_blsct_blocks(self.nodes[0], self.miner_addr, 210)
        self.sync_all()

        self.test_sends(sender, receiver)
        self.test_stakelock(sender)

    def test_sends(self, sender, receiver):
        self.log.info(f"{NUM_SENDS} sends: the returned outputHash is the receiver's output")

        for i in range(NUM_SENDS):
            recv_addr = receiver.getnewaddress(label="", address_type="blsct")
            subtract_fee = i == SUBTRACT_FEE_SEND

            output_hash = sender.sendtoblsctaddress(
                recv_addr, SEND_AMOUNT, f"memo-{i}", False, subtract_fee)
            assert_equal(len(output_hash), 64)

            self.generate_blsct_blocks(self.nodes[0], self.miner_addr, 1)
            self.sync_all()

            # The handle must resolve on chain. A per-transaction fee output
            # survives here (one send per block, so nothing is aggregated
            # away), which is why the ownership check below is what actually
            # separates the recipient output from the fee and change outputs.
            location = self.nodes[0].gettxfromoutputhash(output_hash)
            assert_equal(len(location["txid"]), 64)

            unspent = {u["outid"]: u for u in receiver.listblsctunspent(0, 9999999)}
            assert output_hash in unspent, (
                f"send {i} (subtractfeefromamount={subtract_fee}) returned "
                f"{output_hash}, which is not one of the receiver's outputs: "
                f"the handle points at the sender's change or at the fee output"
            )

            entry = unspent[output_hash]
            assert_equal(entry["address"], recv_addr)
            amount = Decimal(str(entry["amount"]))
            if subtract_fee:
                # The recipient bears the fee, so it receives strictly less
                # than the requested amount -- but not the change output's
                # value, which is what a positional recovery would report.
                assert_greater_than(SEND_AMOUNT, amount)
                assert_greater_than(amount, SEND_AMOUNT - Decimal("0.1"))
            else:
                assert_equal(amount, SEND_AMOUNT)

    def test_stakelock(self, sender):
        self.log.info("stakelock returns the staked commitment's outid")

        output_hash = sender.stakelock(STAKE_AMOUNT)
        assert_equal(len(output_hash), 64)

        self.generate_blsct_blocks(self.nodes[0], self.miner_addr, 1)
        self.sync_all()

        assert_equal(len(self.nodes[0].gettxfromoutputhash(output_hash)["txid"]), 64)

        # liststakedcommitments reports each commitment by its output hash
        # (the `tx_hash` field is the output id BLSCT outpoints are keyed on).
        commitments = sender.liststakedcommitments()
        assert_equal(len(commitments), 1)
        assert_equal(commitments[0]["tx_hash"], output_hash)
        assert_equal(Decimal(commitments[0]["amount"]), STAKE_AMOUNT)


if __name__ == "__main__":
    BlsctSendOutputHashTest(__file__).main()
