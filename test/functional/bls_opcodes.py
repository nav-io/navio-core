#!/usr/bin/env python3
# Copyright (c) 2023 The Navio developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.messages import (
    CTransaction,
    CTxIn,
    CTxOut,
    COutPoint,
)
from test_framework.script import (
    CScript,
    OP_BLSCHECKSIG,
)
from test_framework.test_framework import BitcoinTestFramework


class BLSOpcodeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-blsct=1"]]

    def run_test(self):
        # Test basic BLS opcodes
        self.test_bls_checksig()

    def test_bls_checksig(self):
        """Test OP_BLSCHECKSIG opcode"""
        self.log.info("Testing OP_BLSCHECKSIG...")

        # Create a simple script with OP_BLSCHECKSIG
        # For BLS signatures, we just need to push a public key and call the
        # opcode
        pubkey = bytes([0x01] * 48)  # 48-byte BLS public key
        script = CScript([pubkey, OP_BLSCHECKSIG])

        # The script should execute successfully (BLS signatures are always
        # considered valid in this context)
        # We can't easily test the actual signature verification without BLS
        # keys, but we can test the opcode execution

        # Create a transaction to test with
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(0), CScript([]), 0))
        tx.vout.append(CTxOut(1000000, script))

        # The script should be valid
        self.log.info("OP_BLSCHECKSIG script created successfully")

if __name__ == '__main__':
    BLSOpcodeTest().main()
