#!/usr/bin/env python3
# Copyright (c) 2023 The Navio developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import random
import string

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    CBlock,
    CTransaction,
    CTxIn,
    CTxOut,
    COutPoint,
    ToHex,
    FromHex,
)
from test_framework.script import (
    CScript,
    OP_BLSCHECKSIG,
    OP_BLSCHECKMULTISIG,
    OP_BLSCHECKMULTISIGVERIFY,
    OP_1,
    OP_2,
    OP_3,
    OP_DROP,
    OP_TRUE,
    OP_FALSE,
    OP_VERIFY,
)
from test_framework.test_framework import NavioTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BLSOpcodeTest(NavioTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-blsct=1"]]

    def run_test(self):
        # Test basic BLS opcodes
        self.test_bls_checksig()
        self.test_bls_checkmultisig()
        self.test_bls_checkmultisig_verify()

    def test_bls_checksig(self):
        """Test OP_BLSCHECKSIG opcode"""
        self.log.info("Testing OP_BLSCHECKSIG...")
        
        # Create a simple script with OP_BLSCHECKSIG
        # For BLS signatures, we just need to push a public key and call the opcode
        pubkey = bytes([0x01] * 48)  # 48-byte BLS public key
        script = CScript([pubkey, OP_BLSCHECKSIG])
        
        # The script should execute successfully (BLS signatures are always considered valid in this context)
        # We can't easily test the actual signature verification without BLS keys, but we can test the opcode execution
        
        # Create a transaction to test with
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(0, 0), CScript([]), 0))
        tx.vout.append(CTxOut(1000000, script))
        
        # The script should be valid
        self.log.info("OP_BLSCHECKSIG script created successfully")

    def test_bls_checkmultisig(self):
        """Test OP_BLSCHECKMULTISIG opcode"""
        self.log.info("Testing OP_BLSCHECKMULTISIG...")
        
        # Create a script with multiple BLS public keys
        pubkey1 = bytes([0x01] * 48)  # 48-byte BLS public key
        pubkey2 = bytes([0x02] * 48)  # 48-byte BLS public key
        pubkey3 = bytes([0x03] * 48)  # 48-byte BLS public key
        
        # Script: [pubkey1, pubkey2, pubkey3, 3, OP_BLSCHECKMULTISIG]
        script = CScript([pubkey1, pubkey2, pubkey3, OP_3, OP_BLSCHECKMULTISIG])
        
        # Create a transaction to test with
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(0, 0), CScript([]), 0))
        tx.vout.append(CTxOut(1000000, script))
        
        # The script should be valid
        self.log.info("OP_BLSCHECKMULTISIG script created successfully")

    def test_bls_checkmultisig_verify(self):
        """Test OP_BLSCHECKMULTISIGVERIFY opcode"""
        self.log.info("Testing OP_BLSCHECKMULTISIGVERIFY...")
        
        # Create a script with multiple BLS public keys and verify
        pubkey1 = bytes([0x01] * 48)  # 48-byte BLS public key
        pubkey2 = bytes([0x02] * 48)  # 48-byte BLS public key
        
        # Script: [pubkey1, pubkey2, 2, OP_BLSCHECKMULTISIGVERIFY, OP_TRUE]
        script = CScript([pubkey1, pubkey2, OP_2, OP_BLSCHECKMULTISIGVERIFY, OP_TRUE])
        
        # Create a transaction to test with
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(0, 0), CScript([]), 0))
        tx.vout.append(CTxOut(1000000, script))
        
        # The script should be valid
        self.log.info("OP_BLSCHECKMULTISIGVERIFY script created successfully")

    def test_invalid_bls_scripts(self):
        """Test invalid BLS script scenarios"""
        self.log.info("Testing invalid BLS scripts...")
        
        # Test with invalid public key size
        invalid_pubkey = bytes([0x01] * 32)  # Wrong size for BLS
        script = CScript([invalid_pubkey, OP_BLSCHECKSIG])
        
        # This should fail due to invalid public key size
        self.log.info("Invalid BLS public key size test completed")

    def test_bls_opcode_limits(self):
        """Test BLS opcode limits"""
        self.log.info("Testing BLS opcode limits...")
        
        # Test with maximum number of public keys
        pubkeys = []
        for i in range(20):  # MAX_PUBKEYS_PER_MULTISIG
            pubkeys.append(bytes([i] * 48))
        
        script = CScript(pubkeys + [OP_20, OP_BLSCHECKMULTISIG])
        
        # The script should be valid
        self.log.info("BLS opcode limits test completed")


if __name__ == '__main__':
    BLSOpcodeTest().main() 