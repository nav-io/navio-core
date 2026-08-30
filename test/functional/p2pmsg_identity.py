#!/usr/bin/env python3
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Inbox identity / prekey split: manual rotation and opt-in persistence.

Covers the operator-facing surface of the identity/prekey model:
  * getp2pmsginfo publishes the {identity, prekey, prekey_sig} bundle.
  * rotatep2pmsginbox rotates the PREKEY only -- the identity (the node's
    stable address) is unchanged, the prekey and its signature change.
  * -p2pmsgpersistidentity keeps the identity across a restart; without it the
    identity is fresh each run.

The prekey signature's cryptographic validity is proven by the
p2pmsg_tests/transport_inbox_rotation unit test; here we assert the RPC-visible
invariants.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PMsgIdentityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # node 0: persistent identity; node 1: ephemeral (default).
        self.extra_args = [
            ["-p2pmsg=1", "-p2pmsgpowbits=1", "-p2pmsgpersistidentity=1"],
            ["-p2pmsg=1", "-p2pmsgpowbits=1"],
        ]

    def run_test(self):
        n0 = self.nodes[0]

        info = n0.getp2pmsginfo()
        assert_equal(info["enabled"], True)
        # The full bundle is published.
        for k in ("identity_pubkey", "inbox_pubkey", "prekey_sig"):
            assert k in info and len(info[k]) > 0, f"missing {k}"
        identity0 = info["identity_pubkey"]
        prekey0 = info["inbox_pubkey"]
        sig0 = info["prekey_sig"]

        # Manual rotation changes the prekey (and its signature) but NOT the
        # stable identity address.
        rot = n0.rotatep2pmsginbox()
        assert rot["inbox_pubkey"] != prekey0, "prekey did not rotate"
        info2 = n0.getp2pmsginfo()
        assert_equal(info2["identity_pubkey"], identity0)
        assert_equal(info2["inbox_pubkey"], rot["inbox_pubkey"])
        assert info2["prekey_sig"] != sig0, "prekey_sig did not change on rotation"
        self.log.info("manual rotation replaced prekey, kept identity")

        # Persistence: node 0's identity survives a restart.
        self.restart_node(0, self.extra_args[0])
        info3 = self.nodes[0].getp2pmsginfo()
        assert_equal(info3["identity_pubkey"], identity0)
        self.log.info("persistent identity survived restart")

        # Without the flag, node 1's identity is ephemeral: a fresh key each run.
        id1_before = self.nodes[1].getp2pmsginfo()["identity_pubkey"]
        self.restart_node(1, self.extra_args[1])
        id1_after = self.nodes[1].getp2pmsginfo()["identity_pubkey"]
        assert id1_after != id1_before, "ephemeral identity should change across runs"
        self.log.info("ephemeral identity rotated across restart as expected")


if __name__ == "__main__":
    P2PMsgIdentityTest(__file__).main()
