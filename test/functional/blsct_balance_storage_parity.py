#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""getblsctbalance must exclude staked commitments, whatever the storage flag.

`stakelock`ed funds cannot be spent until `stakeunlock` releases them, so they
belong in getbalances().mine.staked_commitment_balance and must not show up as
available balance. wallet::GetBlsctBalance() buckets them that way for wallets
carrying WALLET_FLAG_BLSCT_OUTPUT_STORAGE; getblsctbalance serves wallets
without the flag from its own mapWallet walk, which has to agree.

The two wallets exercised here hold the same coins and differ only in the
storage flag, which is an on-disk representation choice: getbalances must
report the identical numbers for both.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

FUND_AMOUNT = Decimal("500.00000000")
# blsctregtest requires a minimum stake of 100 NAV.
STAKE_AMOUNT = Decimal("200.00000000")


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

    def stake_and_measure(self, storage_output):
        """Fund a fresh wallet with one output, stake part of it, and return
        (getblsctbalance, getbalances().mine) once the stake is confirmed."""
        node = self.nodes[0]
        name = f"staker_storage_{int(storage_output)}"
        node.createwallet(wallet_name=name, blsct=True, storage_output=storage_output)
        wallet = node.get_wallet_rpc(name)
        addr = wallet.getnewaddress(label="", address_type="blsct")

        self.miner.sendtoblsctaddress(addr, FUND_AMOUNT)
        self.generate_blsct_blocks(self.miner_addr, 1)
        # A single unspent output of a known size, so both wallets under test
        # build the identical stakelock transaction.
        assert_equal(Decimal(str(wallet.getbalance())), FUND_AMOUNT)
        assert_equal(Decimal(str(wallet.getblsctbalance())), FUND_AMOUNT)

        wallet.stakelock(STAKE_AMOUNT)
        self.generate_blsct_blocks(self.miner_addr, 1)

        mine = wallet.getbalances()["mine"]
        blsct_balance = Decimal(str(wallet.getblsctbalance()))
        self.log.info(
            f"storage_output={storage_output}: getblsctbalance={blsct_balance} "
            f"trusted={mine['trusted']} staked={mine['staked_commitment_balance']}")

        staked = Decimal(str(mine["staked_commitment_balance"]))
        trusted = Decimal(str(mine["trusted"]))

        assert_equal(staked, STAKE_AMOUNT)
        # Everything that is left, minus the stakelock fee, is the available
        # balance; the staked commitment is locked and is not part of it.
        assert_greater_than(FUND_AMOUNT - STAKE_AMOUNT, trusted)
        assert_greater_than(trusted, FUND_AMOUNT - STAKE_AMOUNT - Decimal("1"))
        # getblsctbalance reports available balance, so it can never exceed the
        # trusted bucket, and in particular must not carry the staked amount.
        assert_greater_than(trusted + Decimal("0.00000001"), blsct_balance)

        if not storage_output:
            # Without the storage flag getblsctbalance walks mapWallet itself;
            # that walk must bucket staked commitments exactly as
            # wallet::GetBlsctBalance() does, i.e. out of the available balance.
            #
            # The storage_output=True wallet is deliberately not held to this
            # equality: wallet::GetBlsctBalance() skips every mapOutputs entry
            # whose CWalletTx is confirmed or in the mempool (getbalances counts
            # those through GetBalance), so getblsctbalance loses the change of
            # any locally-created BLSCT transaction - a separate defect from the
            # bucketing this test pins.
            assert_equal(blsct_balance, trusted)

        return blsct_balance, mine

    def run_test(self):
        node = self.nodes[0]

        # A separate miner wallet owns every coinbase, so the wallets under
        # test hold exactly what this test sends them.
        node.createwallet(wallet_name="miner", blsct=True)
        self.miner = node.get_wallet_rpc("miner")
        self.miner_addr = self.miner.getnewaddress(label="", address_type="blsct")
        self.generate_blsct_blocks(self.miner_addr, 101)

        self.log.info("Staking on a wallet without WALLET_FLAG_BLSCT_OUTPUT_STORAGE")
        _, mine_no_storage = self.stake_and_measure(False)

        self.log.info("Staking on a wallet with WALLET_FLAG_BLSCT_OUTPUT_STORAGE")
        _, mine_storage = self.stake_and_measure(True)

        self.log.info("The storage flag must not change any getbalances amount")
        for key in ("trusted", "staked_commitment_balance",
                    "pending_staked_commitment_balance", "untrusted_pending",
                    "immature"):
            assert_equal(Decimal(str(mine_no_storage[key])),
                         Decimal(str(mine_storage[key])))


if __name__ == '__main__':
    BlsctBalanceStorageParityTest(__file__).main()
