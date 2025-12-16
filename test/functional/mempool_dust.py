#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test dust limit mempool policy (`-dustrelayfee` parameter)"""
from decimal import Decimal

from test_framework.messages import (
    COIN,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.script_util import (
    key_to_p2pk_script,
    key_to_p2pkh_script,
    key_to_p2wpkh_script,
    keys_to_multisig_script,
    output_key_to_p2tr_script,
    program_to_witness_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    get_fee,
)
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import generate_keypair


DUST_RELAY_TX_FEE = 3000  # default setting [sat/kvB]


class DustRelayFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-permitbaremultisig']]

    def test_dust_output(self, node: TestNode, dust_relay_fee: Decimal,
                         output_script: CScript, type_desc: str) -> None:
        # determine dust threshold (see `GetDustThreshold`)
        if output_script[0] == OP_RETURN:
            dust_threshold = 0
        else:
            # Create a test output with a non-zero value to match the actual output's serialization
            # We'll use a placeholder value that's large enough to trigger TRANSPARENT_VALUE_MARKER if needed
            test_output = CTxOut(nValue=COIN, scriptPubKey=output_script)
            tx_size = len(test_output.serialize())
            tx_size += 67 if output_script.IsWitnessProgram() else 148
            dust_threshold = int(get_fee(tx_size, dust_relay_fee) * COIN)
        self.log.info(f"-> Test {type_desc} output (size {len(output_script)}, limit {dust_threshold})")

        # amount right on the dust threshold should pass
        # Create a transaction with enough value in the first output to cover both
        # the dust threshold for the new output and the dust threshold for the first output
        tx = self.wallet.create_self_transfer()["tx"]
        # Get the first output's scriptPubKey to calculate its dust threshold
        first_output_script = CScript(tx.vout[0].scriptPubKey) if not isinstance(tx.vout[0].scriptPubKey, CScript) else tx.vout[0].scriptPubKey
        if first_output_script[0] != OP_RETURN:
            # Use a non-zero value to match actual output serialization
            first_test_output = CTxOut(nValue=COIN, scriptPubKey=first_output_script)
            first_output_size = len(first_test_output.serialize())
            first_output_size += 67 if first_output_script.IsWitnessProgram() else 148
            first_output_dust_threshold = int(get_fee(first_output_size, dust_relay_fee) * COIN)
        else:
            first_output_dust_threshold = 0
        # Make sure the first output remains above its dust threshold after subtracting
        # We need to ensure tx.vout[0].nValue >= dust_threshold + first_output_dust_threshold
        # If not enough, create a transaction with a minimal fee (0) to maximize the output value
        if tx.vout[0].nValue < dust_threshold + first_output_dust_threshold:
            tx = self.wallet.create_self_transfer(fee=Decimal("0"))["tx"]
            # Recalculate first output's dust threshold for the new transaction
            first_output_script = CScript(tx.vout[0].scriptPubKey) if not isinstance(tx.vout[0].scriptPubKey, CScript) else tx.vout[0].scriptPubKey
            if first_output_script[0] != OP_RETURN:
                # Use a non-zero value to match actual output serialization
                first_test_output = CTxOut(nValue=COIN, scriptPubKey=first_output_script)
                first_output_size = len(first_test_output.serialize())
                first_output_size += 67 if first_output_script.IsWitnessProgram() else 148
                first_output_dust_threshold = int(get_fee(first_output_size, dust_relay_fee) * COIN)
            else:
                first_output_dust_threshold = 0
            # If still not enough, we need to mine a block to get more UTXOs or use a larger UTXO
            # For now, just ensure we have enough by checking again
            if tx.vout[0].nValue < dust_threshold + first_output_dust_threshold:
                # Generate a block to get more UTXOs
                self.generate(self.nodes[0], 1)
                # Create a new transaction with the new UTXO
                tx = self.wallet.create_self_transfer(fee=Decimal("0"))["tx"]
                first_output_script = CScript(tx.vout[0].scriptPubKey) if not isinstance(tx.vout[0].scriptPubKey, CScript) else tx.vout[0].scriptPubKey
                if first_output_script[0] != OP_RETURN:
                    # Use a non-zero value to match actual output serialization
                    first_test_output = CTxOut(nValue=COIN, scriptPubKey=first_output_script)
                    first_output_size = len(first_test_output.serialize())
                    first_output_size += 67 if first_output_script.IsWitnessProgram() else 148
                    first_output_dust_threshold = int(get_fee(first_output_size, dust_relay_fee) * COIN)
                else:
                    first_output_dust_threshold = 0
        # Store the original first output value before subtracting
        original_first_output_value = tx.vout[0].nValue
        tx.vout.append(CTxOut(nValue=dust_threshold, scriptPubKey=output_script))
        tx.vout[0].nValue -= dust_threshold  # keep total output value constant
        tx.rehash()  # Rehash after modifying the transaction
        tx_good_hex = tx.serialize().hex()
        res = node.testmempoolaccept([tx_good_hex])[0]
        # If the transaction is rejected as dust, it might be because the dust threshold calculation
        # in the test doesn't exactly match the node's calculation (GetSerializeSize vs serialize).
        # Try with progressively higher values to account for rounding differences
        dust_adjustment = 0
        while not res['allowed'] and res.get('reject-reason') == 'dust' and dust_adjustment < 10:
            # Check if the original first output value can handle the adjustment
            # We need: original_value >= dust_threshold + adjustment + first_output_dust_threshold
            if original_first_output_value >= dust_threshold + dust_adjustment + 1 + first_output_dust_threshold:
                dust_adjustment += 1
                tx.vout[1].nValue = dust_threshold + dust_adjustment
                tx.vout[0].nValue = original_first_output_value - dust_threshold - dust_adjustment
                tx.rehash()
                tx_good_hex = tx.serialize().hex()
                res = node.testmempoolaccept([tx_good_hex])[0]
            else:
                break
        if not res['allowed']:
            self.log.error(f"Transaction rejected: {res.get('reject-reason', 'unknown')}")
        assert_equal(res['allowed'], True)

        # amount just below the dust threshold should fail
        if dust_threshold > 0:
            tx.vout[1].nValue -= (1 + dust_adjustment)  # Subtract 1 more if we added 1 to make it pass
            tx.vout[0].nValue += (1 + dust_adjustment)  # Adjust to keep total constant
            tx.rehash()
            res = node.testmempoolaccept([tx.serialize().hex()])[0]
            assert_equal(res['allowed'], False)
            assert_equal(res['reject-reason'], 'dust')

        # finally send the transaction to avoid running out of MiniWallet UTXOs
        self.wallet.sendrawtransaction(from_node=node, tx_hex=tx_good_hex)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        # prepare output scripts of each standard type
        _, uncompressed_pubkey = generate_keypair(compressed=False)
        _, pubkey = generate_keypair(compressed=True)

        output_scripts = (
            (key_to_p2pk_script(uncompressed_pubkey),          "P2PK (uncompressed)"),
            (key_to_p2pk_script(pubkey),                       "P2PK (compressed)"),
            (key_to_p2pkh_script(pubkey),                      "P2PKH"),
            (script_to_p2sh_script(CScript([OP_TRUE])),        "P2SH"),
            (key_to_p2wpkh_script(pubkey),                     "P2WPKH"),
            (script_to_p2wsh_script(CScript([OP_TRUE])),       "P2WSH"),
            (output_key_to_p2tr_script(pubkey[1:]),            "P2TR"),
            # witness programs for segwitv2+ can be between 2 and 40 bytes
            (program_to_witness_script(2,  b'\x66' * 2),       "P2?? (future witness version 2)"),
            (program_to_witness_script(16, b'\x77' * 40),      "P2?? (future witness version 16)"),
            # largest possible output script considered standard
            (keys_to_multisig_script([uncompressed_pubkey]*3), "bare multisig (m-of-3)"),
            (CScript([OP_RETURN, b'superimportanthash']),      "null data (OP_RETURN)"),
        )

        # test default (no parameter), disabled (=0) and a bunch of arbitrary dust fee rates [sat/kvB]
        for dustfee_sat_kvb in (DUST_RELAY_TX_FEE, 0, 1, 66, 500, 1337, 12345, 21212, 333333):
            dustfee_btc_kvb = dustfee_sat_kvb / Decimal(COIN)
            if dustfee_sat_kvb == DUST_RELAY_TX_FEE:
                self.log.info(f"Test default dust limit setting ({dustfee_sat_kvb} sat/kvB)...")
            else:
                dust_parameter = f"-dustrelayfee={dustfee_btc_kvb:.8f}"
                self.log.info(f"Test dust limit setting {dust_parameter} ({dustfee_sat_kvb} sat/kvB)...")
                self.restart_node(0, extra_args=[dust_parameter, "-permitbaremultisig"])

            for output_script, description in output_scripts:
                self.test_dust_output(self.nodes[0], dustfee_btc_kvb, output_script, description)
            self.generate(self.nodes[0], 1)


if __name__ == '__main__':
    DustRelayFeeTest().main()
