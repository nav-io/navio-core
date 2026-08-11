#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""getblsctbalance must not depend on WALLET_FLAG_BLSCT_OUTPUT_STORAGE.

The flag is an on-disk representation choice: a wallet carrying it keeps its
BLSCT outputs in mapOutputs, one without it keeps them in mapWallet. Two wallets
holding the same coins must therefore report the same numbers from every balance
RPC.

Two things are pinned here:

* `stakelock`ed funds cannot be spent until `stakeunlock` releases them, so they
  belong in getbalances().mine.staked_commitment_balance and must stay out of
  the available balance in both storage modes.
* The change of a locally-created send is part of the available balance. Under
  output storage that change is recorded both as a CWalletTx and as a mapOutputs
  entry, and getblsctbalance has to count it exactly once.

getbalance, getbalances and getwalletinfo compose GetBalance() with
GetBlsctBalance(); getblsctbalance is BLSCT-only. On these wallets, which hold
no transparent coins at all, all four must agree.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

FUND_AMOUNT = Decimal("500.00000000")
# blsctregtest requires a minimum stake of 100 NAV.
STAKE_AMOUNT = Decimal("200.00000000")
# Two sends, so the second one has no choice but to spend the change of the
# first: that change is the credit the storage path used to lose.
SEND_AMOUNTS = (Decimal("120.00000000"), Decimal("35.00000000"))


def to_dec(value):
    return Decimal(str(value))


class BlsctBalanceStorageParityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_blsct_blocks(self, address, num_blocks, batch_size=2):
        remaining = num_blocks
        while remaining > 0:
            to_generate = min(batch_size, remaining)
            self.generatetoblsctaddress(self.nodes[0], to_generate, address)
            remaining -= to_generate

    def unconfirmed_send_fee(self, wallet):
        """Fee of the one send still sitting unconfirmed in `wallet`.

        sendtoblsctaddress returns an output hash rather than a txid, so the fee
        has to be read back from the transaction list.
        """
        fees = {e["txid"]: -to_dec(e["fee"])
                for e in wallet.listtransactions("*", 10 ** 9, 0, True)
                if e.get("category") == "send" and e.get("confirmations", 1) == 0}
        assert_equal(len(fees), 1)
        fee = next(iter(fees.values()))
        assert_greater_than(fee, Decimal("0"))
        return fee

    def assert_balance_rpcs(self, wallet, expected, scenario):
        """Every balance RPC must report `expected` as the spendable balance.

        getbalance/getbalances/getwalletinfo go through GetBalance() +
        GetBlsctBalance(); getblsctbalance has its own BLSCT-only accounting.
        Holding all four to one independently computed figure is what keeps the
        two paths from drifting.
        """
        mine = wallet.getbalances()["mine"]
        trusted = to_dec(mine["trusted"])
        blsct_balance = to_dec(wallet.getblsctbalance())
        plain_balance = to_dec(wallet.getbalance())
        info_balance = to_dec(wallet.getwalletinfo()["balance"])
        self.log.info(
            f"[{scenario}] expected={expected} getblsctbalance={blsct_balance} "
            f"getbalances.trusted={trusted} getbalance={plain_balance} "
            f"getwalletinfo.balance={info_balance}")
        assert_equal(trusted, expected)
        assert_equal(plain_balance, expected)
        assert_equal(info_balance, expected)
        assert_equal(blsct_balance, expected)
        return mine

    def stake_and_measure(self, storage_output):
        """Fund a fresh wallet with one output, stake part of it, and return
        getbalances().mine once the stake is confirmed."""
        node = self.nodes[0]
        name = f"staker_storage_{int(storage_output)}"
        node.createwallet(wallet_name=name, blsct=True, storage_output=storage_output)
        wallet = node.get_wallet_rpc(name)
        addr = wallet.getnewaddress(label="", address_type="blsct")

        self.miner.sendtoblsctaddress(addr, FUND_AMOUNT)
        self.generate_blsct_blocks(self.miner_addr, 1)
        # A single unspent output of a known size, so both wallets under test
        # build the identical stakelock transaction.
        self.assert_balance_rpcs(wallet, FUND_AMOUNT, f"storage={storage_output} funded")

        wallet.stakelock(STAKE_AMOUNT)
        self.generate_blsct_blocks(self.miner_addr, 1)

        mine = wallet.getbalances()["mine"]
        blsct_balance = to_dec(wallet.getblsctbalance())
        self.log.info(
            f"storage_output={storage_output}: getblsctbalance={blsct_balance} "
            f"trusted={mine['trusted']} staked={mine['staked_commitment_balance']}")

        staked = to_dec(mine["staked_commitment_balance"])
        trusted = to_dec(mine["trusted"])

        assert_equal(staked, STAKE_AMOUNT)
        # Everything that is left, minus the stakelock fee, is the available
        # balance; the staked commitment is locked and is not part of it.
        assert_greater_than(FUND_AMOUNT - STAKE_AMOUNT, trusted)
        assert_greater_than(trusted, FUND_AMOUNT - STAKE_AMOUNT - Decimal("1"))
        # The staked commitment must be bucketed out of the available balance by
        # both accounting paths, so every balance RPC lands on `trusted`.
        self.assert_balance_rpcs(wallet, trusted, f"storage={storage_output} staked")

        return mine

    def spend_and_measure(self, storage_output):
        """Fund a fresh wallet, spend from it twice, and return
        (final spendable balance, getbalances().mine).

        The second send can only be paid from the change of the first, so a
        balance that misses locally-created change shows up here.
        """
        node = self.nodes[0]
        name = f"spender_storage_{int(storage_output)}"
        node.createwallet(wallet_name=name, blsct=True, storage_output=storage_output)
        wallet = node.get_wallet_rpc(name)
        addr = wallet.getnewaddress(label="", address_type="blsct")

        self.miner.sendtoblsctaddress(addr, FUND_AMOUNT)
        self.generate_blsct_blocks(self.miner_addr, 1)
        expected = FUND_AMOUNT
        self.assert_balance_rpcs(wallet, expected, f"storage={storage_output} funded")

        # minconf and include_watchonly are RPC-level plumbing on top of the
        # shared accounting; check they still bite.
        assert_equal(to_dec(wallet.getblsctbalance(1)), expected)
        assert_equal(to_dec(wallet.getblsctbalance(9999)), Decimal("0"))
        assert_equal(to_dec(wallet.getblsctbalance(0, True)), expected)

        for i, amount in enumerate(SEND_AMOUNTS, start=1):
            unspent_before = wallet.listblsctunspent(0, 9999999)
            # One output in, one output out: the next send has to spend the
            # change this one produces.
            assert_equal(len(unspent_before), 1)
            assert_equal(to_dec(unspent_before[0]["amount"]), expected)

            wallet.sendtoblsctaddress(self.miner_addr, amount)
            fee = self.unconfirmed_send_fee(wallet)
            self.generate_blsct_blocks(self.miner_addr, 1)

            expected = expected - amount - fee
            self.assert_balance_rpcs(wallet, expected, f"storage={storage_output} send{i}")

        return expected, wallet.getbalances()["mine"]

    def assert_mine_parity(self, mine_no_storage, mine_storage, scenario):
        self.log.info(f"[{scenario}] the storage flag must not change any getbalances amount")
        for key in ("trusted", "staked_commitment_balance",
                    "pending_staked_commitment_balance", "untrusted_pending",
                    "immature"):
            assert_equal(to_dec(mine_no_storage[key]), to_dec(mine_storage[key]))

    def run_test(self):
        node = self.nodes[0]

        # A separate miner wallet owns every coinbase, so the wallets under
        # test hold exactly what this test sends them.
        node.createwallet(wallet_name="miner", blsct=True)
        self.miner = node.get_wallet_rpc("miner")
        self.miner_addr = self.miner.getnewaddress(label="", address_type="blsct")
        self.generate_blsct_blocks(self.miner_addr, 101)

        self.log.info("Staking on a wallet without WALLET_FLAG_BLSCT_OUTPUT_STORAGE")
        mine_no_storage = self.stake_and_measure(False)

        self.log.info("Staking on a wallet with WALLET_FLAG_BLSCT_OUTPUT_STORAGE")
        mine_storage = self.stake_and_measure(True)

        self.assert_mine_parity(mine_no_storage, mine_storage, "stakelock")

        self.log.info("Spending from a wallet without WALLET_FLAG_BLSCT_OUTPUT_STORAGE")
        spent_no_storage, mine_spent_no_storage = self.spend_and_measure(False)

        self.log.info("Spending from a wallet with WALLET_FLAG_BLSCT_OUTPUT_STORAGE")
        spent_storage, mine_spent_storage = self.spend_and_measure(True)

        assert_equal(spent_no_storage, spent_storage)
        self.assert_mine_parity(mine_spent_no_storage, mine_spent_storage, "sends")


if __name__ == '__main__':
    BlsctBalanceStorageParityTest(__file__).main()
