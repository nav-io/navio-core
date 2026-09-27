#!/usr/bin/env python3
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test gettxoutproof and verifytxoutproof RPCs."""

from test_framework.messages import (
    CMerkleBlock,
    from_hex,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


class MerkleBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [
            [],
            ["-txindex"],
        ]

    def run_test(self):
        miniwallet = MiniWallet(self.nodes[0])

        chain_height = self.nodes[1].getblockcount()
        assert_equal(chain_height, 200)

        res1 = miniwallet.send_self_transfer(from_node=self.nodes[0])
        txid1 = res1['txid']
        outid1 = res1['new_utxo']['txid']  # hash of txid1's output
        res2 = miniwallet.send_self_transfer(from_node=self.nodes[0])
        txid2 = res2['txid']
        outid2 = res2['new_utxo']['txid']  # hash of txid2's output
        self.sync_mempools()

        # This will raise an exception because the transaction is not yet in a block
        assert_raises_rpc_error(-5, "Transaction not yet in block", self.nodes[1].gettxoutproof, [txid1])
        assert_raises_rpc_error(-5, "Transaction not found in the utxo set; specify the block hash or enable -txindex", self.nodes[0].gettxoutproof, [outid1])

        self.generate(self.nodes[0], 1)
        blockhash = self.nodes[0].getblockhash(chain_height + 1)

        txlist = []
        blocktxn = self.nodes[0].getblock(blockhash, True)["tx"]
        txlist.append(blocktxn[1])
        txlist.append(blocktxn[2])

        # With -txindex, transactions are located by their txid
        assert_equal(self.nodes[1].verifytxoutproof(self.nodes[1].gettxoutproof([txid1])), [txid1])
        assert_equal(self.nodes[1].verifytxoutproof(self.nodes[1].gettxoutproof([txid1, txid2])), txlist)
        assert_equal(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([txid1, txid2], blockhash)), txlist)

        # Without -txindex, a txid alone cannot be located
        assert_raises_rpc_error(-5, "Transaction not found in the utxo set; specify the block hash or enable -txindex", self.nodes[0].gettxoutproof, [txid1])
        # ... but the hash of an unspent output can, and the proof commits to the transaction holding it
        assert_equal(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([outid1])), [txid1])
        assert_equal(self.nodes[1].verifytxoutproof(self.nodes[1].gettxoutproof([outid1])), [txid1])
        # Output hashes and txids can be mixed, in any order
        assert_equal(sorted(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([outid1, txid2]))), sorted(txlist))
        assert_equal(sorted(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([txid2, outid1]))), sorted(txlist))
        assert_equal(sorted(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([outid1, outid2]))), sorted(txlist))
        # Output hashes also resolve against a given block
        assert_equal(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([outid2], blockhash)), [txid2])

        txin_spent = miniwallet.get_utxo(txid=outid2)  # Get the change from txid2
        tx3 = miniwallet.send_self_transfer(from_node=self.nodes[0], utxo_to_spend=txin_spent)
        txid3 = tx3['txid']
        outid3 = tx3['new_utxo']['txid']
        self.generate(self.nodes[0], 1)

        txid_spent = txid2  # The transaction that created the spent output
        txid_unspent = txid1  # This should be unspent

        # Invalid txids
        assert_raises_rpc_error(-8, "txid must be of length 64 (not 32, for '00000000000000000000000000000000')", self.nodes[0].gettxoutproof, ["00000000000000000000000000000000"], blockhash)
        assert_raises_rpc_error(-8, "txid must be hexadecimal string (not 'ZZZ0000000000000000000000000000000000000000000000000000000000000')", self.nodes[0].gettxoutproof, ["ZZZ0000000000000000000000000000000000000000000000000000000000000"], blockhash)
        # Invalid blockhashes
        assert_raises_rpc_error(-8, "blockhash must be of length 64 (not 32, for '00000000000000000000000000000000')", self.nodes[0].gettxoutproof, [txid_spent], "00000000000000000000000000000000")
        assert_raises_rpc_error(-8, "blockhash must be hexadecimal string (not 'ZZZ0000000000000000000000000000000000000000000000000000000000000')", self.nodes[0].gettxoutproof, [txid_spent], "ZZZ0000000000000000000000000000000000000000000000000000000000000")
        # We can't find the block from a spent output without -txindex
        assert_raises_rpc_error(-5, "Transaction not found in the utxo set; specify the block hash or enable -txindex", self.nodes[0].gettxoutproof, [outid2])
        # We can get the proof if we specify the block
        assert_equal(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([txid_spent], blockhash)), [txid_spent])
        assert_equal(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([outid2], blockhash)), [txid_spent])
        # We can't get the proof if we specify a non-existent block
        assert_raises_rpc_error(-5, "Block not found", self.nodes[0].gettxoutproof, [txid_spent], "0000000000000000000000000000000000000000000000000000000000000000")
        # We can get the proof if the output is unspent
        assert_equal(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([outid1])), [txid_unspent])
        # We can get the proof if we provide a list of ids and one of them is an unspent output. The ordering of the list should not matter.
        assert_equal(sorted(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([outid1, txid2]))), sorted(txlist))
        assert_equal(sorted(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([txid2, outid1]))), sorted(txlist))
        # We can always get a proof if we have a -txindex
        assert_equal(self.nodes[0].verifytxoutproof(self.nodes[1].gettxoutproof([txid_spent])), [txid_spent])
        assert_equal(sorted(self.nodes[0].verifytxoutproof(self.nodes[1].gettxoutproof([txid2, txid1]))), sorted(txlist))
        # The newer block is found too, through either kind of id
        assert_equal(self.nodes[1].verifytxoutproof(self.nodes[1].gettxoutproof([txid3])), [txid3])
        assert_equal(self.nodes[0].verifytxoutproof(self.nodes[0].gettxoutproof([outid3])), [txid3])
        # We can't get a proof if we specify transactions from different blocks
        assert_raises_rpc_error(-5, "Not all transactions found in specified or retrieved block", self.nodes[1].gettxoutproof, [txid1, txid3])
        assert_raises_rpc_error(-5, "Not all transactions found in specified or retrieved block", self.nodes[0].gettxoutproof, [outid1, outid3])
        # Test empty list
        assert_raises_rpc_error(-8, "Parameter 'txids' cannot be empty", self.nodes[0].gettxoutproof, [])
        # Test duplicate txid
        assert_raises_rpc_error(-8, 'Invalid parameter, duplicated txid', self.nodes[0].gettxoutproof, [txid1, txid1])

        # Now we'll try tweaking a proof.
        proof = self.nodes[1].gettxoutproof([txid1, txid2])
        assert txid1 in self.nodes[0].verifytxoutproof(proof)
        assert txid2 in self.nodes[1].verifytxoutproof(proof)

        tweaked_proof = from_hex(CMerkleBlock(), proof)

        # Make sure that our serialization/deserialization is working
        assert txid1 in self.nodes[0].verifytxoutproof(tweaked_proof.serialize().hex())

        # Check to see if we can go up the merkle tree and pass this off as a
        # single-transaction block
        tweaked_proof.txn.nTransactions = 1
        tweaked_proof.txn.vHash = [tweaked_proof.header.hashMerkleRoot]
        tweaked_proof.txn.vBits = [True] + [False]*7

        for n in self.nodes:
            assert not n.verifytxoutproof(tweaked_proof.serialize().hex())

        # TODO: try more variants, eg transactions at different depths, and
        # verify that the proofs are invalid

if __name__ == '__main__':
    MerkleBlockTest(__file__).main()
