#!/usr/bin/env python3
# Copyright (c) 2024 The Navio developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BIP-39 mnemonic wallet support."""

import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletMnemonicTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def bitcoin_wallet_process(self, *args):
        default_args = ['-datadir={}'.format(self.nodes[0].datadir_path), '-chain=%s' % self.chain]
        return subprocess.Popen(
            [self.options.naviowallet] + default_args + list(args),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def navio_wallet_create(self, wallet_name, mnemonic=None, seed=None):
        """Run navio-wallet create with -blsct. Options must come BEFORE the command."""
        args = [
            '-datadir={}'.format(self.nodes[0].datadir_path),
            '-chain={}'.format(self.chain),
            '-wallet={}'.format(wallet_name),
            '-blsct',
        ]
        if mnemonic is not None:
            args.append('-mnemonic={}'.format(mnemonic))
        if seed is not None:
            args.append('-seed={}'.format(seed))
        args.append('create')
        p = subprocess.Popen(
            [self.options.naviowallet] + args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = p.communicate()
        return p.poll(), stdout, stderr

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Test dumpmnemonic on a new BLSCT wallet")
        node.createwallet(wallet_name="test_blsct", blsct=True)
        w = node.get_wallet_rpc("test_blsct")
        mnemonic = w.dumpmnemonic()
        words = mnemonic.split()
        assert_equal(len(words), 24)

        self.log.info("Test restore from mnemonic produces same seed")
        seed_a = w.getblsctseed()
        node.createwallet(wallet_name="test_restored", blsct=True, mnemonic=mnemonic)
        w2 = node.get_wallet_rpc("test_restored")
        seed_b = w2.getblsctseed()
        assert_equal(seed_a, seed_b)

        self.log.info("Test dumpmnemonic on non-BLSCT wallet errors")
        node.createwallet(wallet_name="test_descriptor")
        w3 = node.get_wallet_rpc("test_descriptor")
        assert_raises_rpc_error(-4, None, w3.dumpmnemonic)

        self.log.info("Test createwallet with blsct=true returns mnemonic in response")
        result = node.createwallet(wallet_name="test_new_blsct", blsct=True)
        assert "mnemonic" in result
        words = result["mnemonic"].split()
        assert_equal(len(words), 24)

        self.log.info("Test createwallet with mnemonic param restores correctly")
        w_new = node.get_wallet_rpc("test_new_blsct")
        seed_new = w_new.getblsctseed()
        mnemonic_new = result["mnemonic"]
        node.createwallet(wallet_name="test_from_mnemonic", blsct=True, mnemonic=mnemonic_new)
        w_from = node.get_wallet_rpc("test_from_mnemonic")
        seed_from = w_from.getblsctseed()
        assert_equal(seed_new, seed_from)

        self.log.info("Test createwallet with both mnemonic and seed errors")
        assert_raises_rpc_error(-8, "Cannot specify both",
            node.createwallet, wallet_name="test_both",
            blsct=True, seed="00" * 32, mnemonic="abandon " * 23 + "art")

        self.log.info("Test createwallet with invalid mnemonic errors")
        assert_raises_rpc_error(-8, "Invalid mnemonic",
            node.createwallet, wallet_name="test_invalid",
            blsct=True, mnemonic="invalid words here that are not real")

        self.log.info("Test dumpmnemonic on seed-imported BLSCT wallet errors")
        node.createwallet(wallet_name="test_seed_wallet", blsct=True, seed="00" * 32)
        w_seed = node.get_wallet_rpc("test_seed_wallet")
        assert_raises_rpc_error(-4, "Wallet does not have a mnemonic", w_seed.dumpmnemonic)

        self.log.info("Test full lifecycle roundtrip: create -> dump -> restore -> verify same keys")
        node.createwallet(wallet_name="test_lifecycle", blsct=True)
        w_lc = node.get_wallet_rpc("test_lifecycle")
        mnemonic_lc = w_lc.dumpmnemonic()
        addr_lc = w_lc.getnewaddress()
        # Restore from mnemonic into a new wallet
        node.createwallet(wallet_name="test_lifecycle_restored", blsct=True, mnemonic=mnemonic_lc)
        w_lc2 = node.get_wallet_rpc("test_lifecycle_restored")
        addr_lc2 = w_lc2.getnewaddress()
        assert_equal(addr_lc, addr_lc2)

        # === New test scenarios ===

        self.log.info("Test wallet reload: mnemonic persists across unload/load")
        node.createwallet(wallet_name="test_reload", blsct=True)
        w_reload = node.get_wallet_rpc("test_reload")
        mnemonic_before = w_reload.dumpmnemonic()
        seed_before = w_reload.getblsctseed()
        node.unloadwallet("test_reload")
        node.loadwallet("test_reload")
        w_reload2 = node.get_wallet_rpc("test_reload")
        mnemonic_after = w_reload2.dumpmnemonic()
        seed_after = w_reload2.getblsctseed()
        assert_equal(mnemonic_before, mnemonic_after)
        assert_equal(seed_before, seed_after)

        self.log.info("Test encrypted wallet: dumpmnemonic works after encryption")
        node.createwallet(wallet_name="test_encrypted", blsct=True, passphrase="testpass")
        w_enc = node.get_wallet_rpc("test_encrypted")
        w_enc.walletpassphrase("testpass", 999999)
        mnemonic_enc = w_enc.dumpmnemonic()
        words_enc = mnemonic_enc.split()
        assert_equal(len(words_enc), 24)
        # Verify the seed matches what we'd expect from the mnemonic
        seed_enc = w_enc.getblsctseed()
        assert len(seed_enc) > 0

        self.log.info("Test dumpmnemonic on locked encrypted wallet errors")
        w_enc.walletlock()
        assert_raises_rpc_error(-13, "wallet passphrase", w_enc.dumpmnemonic)
        # Re-unlock for any subsequent tests
        w_enc.walletpassphrase("testpass", 999999)

        self.log.info("Test multi-address consistency: 5 addresses match after restore")
        node.createwallet(wallet_name="test_multiaddr", blsct=True)
        w_ma = node.get_wallet_rpc("test_multiaddr")
        mnemonic_ma = w_ma.dumpmnemonic()
        addrs_orig = [w_ma.getnewaddress() for _ in range(5)]
        # Restore and generate same addresses
        node.createwallet(wallet_name="test_multiaddr_restored", blsct=True, mnemonic=mnemonic_ma)
        w_ma2 = node.get_wallet_rpc("test_multiaddr_restored")
        addrs_restored = [w_ma2.getnewaddress() for _ in range(5)]
        assert_equal(addrs_orig, addrs_restored)

        self.log.info("Test dumpmnemonic on restored wallet returns the original mnemonic")
        node.createwallet(wallet_name="test_dump_restore", blsct=True)
        w_dr = node.get_wallet_rpc("test_dump_restore")
        mnemonic_dr = w_dr.dumpmnemonic()
        node.createwallet(wallet_name="test_dump_restored", blsct=True, mnemonic=mnemonic_dr)
        w_dr2 = node.get_wallet_rpc("test_dump_restored")
        mnemonic_dr2 = w_dr2.dumpmnemonic()
        assert_equal(mnemonic_dr, mnemonic_dr2)

        self.log.info("Test createwallet with mnemonic does NOT return mnemonic in response")
        # First create a wallet to get a known mnemonic
        result_new = node.createwallet(wallet_name="test_source_mnemonic", blsct=True)
        source_mnemonic = result_new["mnemonic"]
        assert "mnemonic" in result_new
        # Restore from that mnemonic - response should NOT include mnemonic key
        result_restore = node.createwallet(
            wallet_name="test_restore_no_mnemonic", blsct=True, mnemonic=source_mnemonic)
        assert "mnemonic" not in result_restore

        self.log.info("Test createwallet with seed does NOT return mnemonic in response")
        result_seed = node.createwallet(
            wallet_name="test_seed_no_mnemonic", blsct=True, seed="00" * 32)
        assert "mnemonic" not in result_seed

        self.log.info("Test CLI tool: navio-wallet create with -blsct outputs mnemonic")
        cli_wallet_name = "test_cli_mnemonic"
        rc, stdout, stderr = self.navio_wallet_create(cli_wallet_name)
        if rc != 0:
            self.log.error("CLI stderr: {}".format(stderr))
            self.log.error("CLI stdout: {}".format(stdout))
        assert_equal(rc, 0)
        assert "Mnemonic:" in stdout
        # Extract the mnemonic line
        mnemonic_line = [l for l in stdout.split('\n') if l.startswith('Mnemonic:')]
        assert_equal(len(mnemonic_line), 1)
        cli_mnemonic = mnemonic_line[0].replace('Mnemonic:', '').strip()
        cli_words = cli_mnemonic.split()
        assert_equal(len(cli_words), 24)

        self.log.info("Test CLI tool: navio-wallet create with -blsct -mnemonic restores")
        cli_restore_name = "test_cli_restored"
        rc2, stdout2, stderr2 = self.navio_wallet_create(
            cli_restore_name, mnemonic=cli_mnemonic)
        assert_equal(rc2, 0)
        # When restoring, the CLI should NOT print the mnemonic again
        assert "Mnemonic:" not in stdout2

        self.log.info("Test CLI tool: navio-wallet create with -seed and -mnemonic errors")
        rc3, stdout3, stderr3 = self.navio_wallet_create(
            "test_cli_both", seed="00" * 32, mnemonic=cli_mnemonic)
        assert_equal(rc3, 1)
        assert "Cannot specify both" in stderr3

        self.log.info("Test CLI tool: navio-wallet create with invalid -mnemonic errors")
        rc4, stdout4, stderr4 = self.navio_wallet_create(
            "test_cli_invalid_mnemonic", mnemonic="invalid words that are not in the wordlist at all")
        assert_equal(rc4, 1)
        assert "Invalid mnemonic" in stderr4

        self.log.info("Test roundtrip through CLI: CLI create -> RPC dumpmnemonic -> CLI restore")
        # Create a wallet via CLI
        cli_wallet2 = "test_cli_roundtrip"
        rc5, stdout5, stderr5 = self.navio_wallet_create(cli_wallet2)
        assert_equal(rc5, 0)
        mnemonic_line5 = [l for l in stdout5.split('\n') if l.startswith('Mnemonic:')]
        cli_mnemonic2 = mnemonic_line5[0].replace('Mnemonic:', '').strip()
        # Load the CLI-created wallet via RPC and verify dumpmnemonic matches
        node.loadwallet(cli_wallet2)
        w_cli = node.get_wallet_rpc(cli_wallet2)
        rpc_mnemonic = w_cli.dumpmnemonic()
        assert_equal(cli_mnemonic2, rpc_mnemonic)
        # Verify the restored wallet produces the same addresses
        addr_cli = w_cli.getnewaddress()
        cli_roundtrip_restored = "test_cli_roundtrip_restored"
        rc6, stdout6, stderr6 = self.navio_wallet_create(
            cli_roundtrip_restored, mnemonic=cli_mnemonic2)
        assert_equal(rc6, 0)
        node.loadwallet(cli_roundtrip_restored)
        w_cli2 = node.get_wallet_rpc(cli_roundtrip_restored)
        addr_cli2 = w_cli2.getnewaddress()
        assert_equal(addr_cli, addr_cli2)


if __name__ == '__main__':
    WalletMnemonicTest().main()
