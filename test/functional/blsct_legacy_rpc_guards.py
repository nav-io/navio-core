#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional tests for the BLSCT guards on legacy ECDSA/script wallet RPCs.

navio's proper wallet format is BLSCT. A handful of legacy ECDSA/script wallet
RPCs either give a confusing internal error on a BLSCT wallet, or -- worse --
silently do the wrong thing. The most dangerous case is `dumpwallet`, which
dumps only the wallet's transparent (ECDSA) keys/scripts and gives no
indication that the BLS keys were not backed up at all.

This test asserts that:
 - dumpwallet, importwallet, sethdseed, and signmessage (on a BLSCT address)
   all raise clear, actionable errors naming the correct BLSCT equivalent when
   used on a BLSCT wallet.
 - importdescriptors/listdescriptors continue to raise their existing (already
   clear) "non-descriptor wallet" errors on a BLSCT wallet (left unchanged;
   asserted here to document the contract).
 - On an fBLSCT chain (both mainnet and testnet, and this blsctregtest chain),
   ConnectBlock consensus-rejects any non-coinbase transparent transaction
   ("non-blsct-tx-not-allowed"). Transparent (ECDSA) keys can therefore never
   send or usefully receive funds on this chain, for ANY wallet -- not just
   BLSCT-flagged ones. importprivkey/dumpprivkey/importaddress/importpubkey/
   importmulti are guarded on Params().GetConsensus().fBLSCT (a chain-level
   property, not the wallet's BLSCT flag) and now raise a clear error here.
 - A plain (non-BLSCT) wallet on this same fBLSCT chain is still subject to
   the chain-level guard (dumpwallet/sethdseed/signmessage remain unaffected
   since those are gated on the wallet's own BLSCT flag, not the chain).
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BLSCTLegacyRPCGuardsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, blsct=True)

    def set_test_params(self):
        self.num_nodes = 1
        self.chain = 'blsctregtest'
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create a BLSCT wallet")
        node.createwallet(wallet_name="blsct_guards", blsct=True)
        blsct_wallet = node.get_wallet_rpc("blsct_guards")

        self.test_dumpwallet_guard(blsct_wallet)
        self.test_importwallet_guard(blsct_wallet)
        self.test_sethdseed_guard(blsct_wallet)
        self.test_signmessage_guard(blsct_wallet)
        self.test_preexisting_descriptor_guards(blsct_wallet)
        self.test_transparent_key_rpcs_guarded(blsct_wallet)
        self.test_legacy_wallet_unaffected()

    def test_dumpwallet_guard(self, wallet):
        self.log.info("dumpwallet on a BLSCT wallet raises a clear guard error")
        dump_path = os.path.join(self.options.tmpdir, 'blsct_dumpwallet_should_not_exist.txt')
        assert_raises_rpc_error(
            -4,
            "dumpwallet only backs up this wallet's transparent (ECDSA) keys",
            wallet.dumpwallet,
            dump_path,
        )
        assert not os.path.exists(dump_path)

    def test_importwallet_guard(self, wallet):
        self.log.info("importwallet on a BLSCT wallet raises a clear guard error")
        # The guard fires before the file is even opened, so a nonexistent
        # path is fine here.
        assert_raises_rpc_error(
            -4,
            "importwallet only imports transparent (ECDSA) keys",
            wallet.importwallet,
            os.path.join(self.options.tmpdir, 'does_not_matter.txt'),
        )

    def test_sethdseed_guard(self, wallet):
        self.log.info("sethdseed on a BLSCT wallet raises a clear guard error")
        assert_raises_rpc_error(
            -4,
            "sethdseed only sets the seed for this wallet's legacy transparent keychain",
            wallet.sethdseed,
        )

    def test_signmessage_guard(self, wallet):
        self.log.info("signmessage on a BLSCT address raises a clear guard error")
        blsct_addr = wallet.getnewaddress(label="", address_type="blsct")
        assert_raises_rpc_error(
            -3,
            "Address is a BLSCT address; signmessage only supports transparent (ECDSA) addresses. Use signblsmessage",
            wallet.signmessage,
            blsct_addr,
            "hello",
        )

    def test_preexisting_descriptor_guards(self, wallet):
        self.log.info("importdescriptors/listdescriptors already error clearly on a BLSCT wallet (left unchanged)")
        assert_raises_rpc_error(
            -4,
            "importdescriptors is not available for non-descriptor wallets",
            wallet.importdescriptors,
            [{"desc": "pkh(0000000000000000000000000000000000000000000000000000000000000001)", "timestamp": "now"}],
        )
        assert_raises_rpc_error(
            -4,
            "listdescriptors is not available for non-descriptor wallets",
            wallet.listdescriptors,
        )

    def test_transparent_key_rpcs_guarded(self, wallet):
        """navio's mainnet/testnet (and this blsctregtest chain) set
        consensus.fBLSCT=true, so ConnectBlock consensus-rejects any
        non-coinbase transparent transaction ("non-blsct-tx-not-allowed").
        A transparent (ECDSA) key can therefore never send or usefully
        receive funds on this chain, for ANY wallet -- not just BLSCT-flagged
        ones. importprivkey/dumpprivkey/importaddress/importpubkey/
        importmulti are guarded on Params().GetConsensus().fBLSCT (the
        chain's consensus flag, not the wallet's BLSCT flag) and now raise a
        clear error here instead of silently operating on dead keys."""
        self.log.info("Transparent-key import/dump RPCs raise a clear guard error on an fBLSCT chain")

        legacy_addr = wallet.getnewaddress(label="", address_type="legacy")

        assert_raises_rpc_error(
            -4,
            "transparent (ECDSA) keys cannot send or receive here, so dumpprivkey is not available",
            wallet.dumpprivkey,
            legacy_addr,
        )

        assert_raises_rpc_error(
            -4,
            "transparent (ECDSA) keys cannot send or receive here, so importprivkey is not available",
            wallet.importprivkey,
            "cNotAValidKeyButTheGuardFiresBeforeItIsParsed",
        )

        assert_raises_rpc_error(
            -4,
            "transparent (ECDSA) addresses cannot send or receive here, so importaddress is not available",
            wallet.importaddress,
            legacy_addr,
        )

        assert_raises_rpc_error(
            -4,
            "transparent (ECDSA) keys cannot send or receive here, so importpubkey is not available",
            wallet.importpubkey,
            "03" + "00" * 32,
        )

        assert_raises_rpc_error(
            -4,
            "transparent (ECDSA) keys/scripts cannot send or receive here, so importmulti is not available",
            wallet.importmulti,
            [{
                "scriptPubKey": {"address": legacy_addr},
                "timestamp": "now",
                "watchonly": True,
            }],
        )

        # signmessage on a transparent address inside a BLSCT wallet is
        # unaffected: it only signs a message with the key, it does not
        # touch transparent-tx spendability, so it keeps working.
        sig = wallet.signmessage(legacy_addr, "hello transparent")
        assert sig

    def test_legacy_wallet_unaffected(self):
        """A plain (non-BLSCT-flagged) wallet is unaffected by the 4
        wallet-flag guards (dumpwallet/sethdseed/signmessage/importwallet),
        since those only fire when WALLET_FLAG_BLSCT is set on the wallet.
        But this node's chain is still blsctregtest (fBLSCT=true), so the
        chain-level guard on importprivkey/dumpprivkey/importaddress/
        importpubkey/importmulti still applies -- it does not care about the
        wallet's own flags, only the chain's consensus rules."""
        self.log.info("A plain legacy (non-BLSCT) wallet is unaffected by the 4 wallet-flag guards")
        self.nodes[0].createwallet(wallet_name="legacy_guards", descriptors=False, blsct=False)
        legacy_wallet = self.nodes[0].get_wallet_rpc("legacy_guards")

        dump_path = os.path.join(self.options.tmpdir, 'legacy_dump.txt')
        result = legacy_wallet.dumpwallet(dump_path)
        assert_equal(result["filename"], dump_path)
        assert os.path.exists(dump_path)

        legacy_wallet.sethdseed()

        addr = legacy_wallet.getnewaddress(label="", address_type="legacy")
        sig = legacy_wallet.signmessage(addr, "hello legacy")
        assert sig

        self.nodes[0].createwallet(wallet_name="legacy_guards_importer", descriptors=False, blsct=False)
        importer = self.nodes[0].get_wallet_rpc("legacy_guards_importer")
        importer.importwallet(dump_path)

        self.log.info("...but the chain-level fBLSCT guard still applies to this plain wallet's transparent-key RPCs")
        assert_raises_rpc_error(
            -4,
            "transparent (ECDSA) keys cannot send or receive here, so dumpprivkey is not available",
            legacy_wallet.dumpprivkey,
            addr,
        )
        assert_raises_rpc_error(
            -4,
            "transparent (ECDSA) keys cannot send or receive here, so importprivkey is not available",
            importer.importprivkey,
            "cNotAValidKeyButTheGuardFiresBeforeItIsParsed",
        )


if __name__ == '__main__':
    BLSCTLegacyRPCGuardsTest(__file__).main()
