#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A limited-functionality wallet, which may replace a real wallet in tests"""

from copy import deepcopy
from decimal import Decimal
from enum import Enum
from typing import (
    Any,
    Optional,
)
from test_framework.address import (
    address_to_scriptpubkey,
    create_deterministic_address_bcrt1_p2tr_op_true,
    key_to_p2pkh,
    key_to_p2sh_p2wpkh,
    key_to_p2wpkh,
    output_key_to_p2tr,
)
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import descsum_create
from test_framework.key import (
    ECKey,
    compute_xonly_pubkey,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    OP_NOP,
    OP_RETURN,
    OP_TRUE,
    sign_input_legacy,
    taproot_construct,
)
from test_framework.script_util import (
    key_to_p2pk_script,
    key_to_p2pkh_script,
    key_to_p2sh_p2wpkh_script,
    key_to_p2wpkh_script,
)
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
)
from test_framework.wallet_util import generate_keypair
import random

DEFAULT_FEE = Decimal("0.0001")

class MiniWalletMode(Enum):
    """Determines the transaction type the MiniWallet is creating and spending.

    For most purposes, the default mode ADDRESS_OP_TRUE should be sufficient;
    it simply uses a fixed bech32m P2TR address whose coins are spent with a
    witness stack of OP_TRUE, i.e. following an anyone-can-spend policy.
    However, if the transactions need to be modified by the user (e.g. prepending
    scriptSig for testing opcodes that are activated by a soft-fork), or the txs
    should contain an actual signature, the raw modes RAW_OP_TRUE and RAW_P2PK
    can be useful. Summary of modes:

                    |      output       |           |  tx is   | can modify |  needs
         mode       |    description    |  address  | standard | scriptSig  | signing
    ----------------+-------------------+-----------+----------+------------+----------
    ADDRESS_OP_TRUE | anyone-can-spend  |  bech32m  |   yes    |    no      |   no
    RAW_OP_TRUE     | anyone-can-spend  |  - (raw)  |   no     |    yes     |   no
    RAW_P2PK        | pay-to-public-key |  - (raw)  |   yes    |    yes     |   yes
    """
    ADDRESS_OP_TRUE = 1
    RAW_OP_TRUE = 2
    RAW_P2PK = 3


class MiniWallet:
    def __init__(self, test_node, *, mode=MiniWalletMode.ADDRESS_OP_TRUE):
        self._test_node = test_node
        self._utxos = []
        self._mode = mode

        assert isinstance(mode, MiniWalletMode)
        if mode == MiniWalletMode.RAW_OP_TRUE:
            self._scriptPubKey = bytes(CScript([OP_TRUE]))
        elif mode == MiniWalletMode.RAW_P2PK:
            # use simple deterministic private key (k=1)
            self._priv_key = ECKey()
            self._priv_key.set((1).to_bytes(32, 'big'), True)
            pub_key = self._priv_key.get_pubkey()
            self._scriptPubKey = key_to_p2pk_script(pub_key.get_bytes())
        elif mode == MiniWalletMode.ADDRESS_OP_TRUE:
            self._address, self._internal_key = create_deterministic_address_bcrt1_p2tr_op_true()
            self._scriptPubKey = address_to_scriptpubkey(self._address)

        # When the pre-mined test framework chain is used, it contains coinbase
        # outputs to the MiniWallet's default address in blocks 76-100
        # (see method BitcoinTestFramework._initialize_chain())
        # The MiniWallet needs to rescan_utxos() in order to account
        # for those mature UTXOs, so that all txs spend confirmed coins
        self.rescan_utxos()

    def _create_utxo(self, *, txid, value, height, coinbase, confirmations):
        if isinstance(txid, int):
            txid = f"{txid:064x}"
        return {"txid": txid, "value": value, "height": height, "coinbase": coinbase, "confirmations": confirmations}

    def _bulk_tx(self, tx, target_weight):
        """Pad a transaction with extra outputs until it reaches a target weight (or higher).
        returns the tx
        """
        tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN, b'a'])))
        dummy_vbytes = (target_weight - tx.get_weight() + 3) // 4
        tx.vout[-1].scriptPubKey = CScript([OP_RETURN, b'a' * dummy_vbytes])
        # Lower bound should always be off by at most 3
        assert_greater_than_or_equal(tx.get_weight(), target_weight)
        # Higher bound should always be off by at most 3 + 12 weight (for encoding the length)
        assert_greater_than_or_equal(target_weight + 15, tx.get_weight())

    def get_balance(self):
        return sum(u['value'] for u in self._utxos)

    def rescan_utxos(self, *, include_mempool=True):
        """Drop all utxos and rescan the utxo set"""
        self._utxos = []
        res = self._test_node.scantxoutset(action="start", scanobjects=[self.get_descriptor()])
        assert_equal(True, res['success'])
        for utxo in res['unspents']:
            self._utxos.append(
                self._create_utxo(txid=utxo["txid"],
                                  value=utxo["amount"],
                                  height=utxo["height"],
                                  coinbase=utxo["coinbase"],
                                  confirmations=res["height"] - utxo["height"] + 1))
        if include_mempool:
            mempool = self._test_node.getrawmempool(verbose=True)
            # Sort tx by ancestor count. See BlockAssembler::SortForBlock in src/node/miner.cpp
            sorted_mempool = sorted(mempool.items(), key=lambda item: (item[1]["ancestorcount"], int(item[0], 16)))
            for txid, _ in sorted_mempool:
                self.scan_tx(self._test_node.getrawtransaction(txid=txid, verbose=True))

    def scan_tx(self, tx):
        """Scan the tx and adjust the internal list of owned utxos"""
        for spent in tx["vin"]:
            # Mark spent. This may happen when the caller has ownership of a
            # utxo that remained in this wallet. For example, by passing
            # mark_as_spent=False to get_utxo or by using an utxo returned by a
            # create_self_transfer* call.
            # Handle both "txid" and "hash" fields (for output hash prevout system)
            spent_txid = spent.get("txid") or spent.get("hash")
            if spent_txid:
                try:
                    self.get_utxo(txid=spent_txid)
                except StopIteration:
                    pass
        # Get the transaction hash from the transaction details
        tx_hash = tx.get('txid') or tx.get('hash')
        for out in tx['vout']:
            if out['scriptPubKey']['hex'] == self._scriptPubKey.hex():
                utxo = self._create_utxo(txid=out['hash'], value=out["value"], height=0, coinbase=False, confirmations=0)
                # Add transaction_txid field if we have the transaction hash
                if tx_hash:
                    utxo['transaction_txid'] = tx_hash
                self._utxos.append(utxo)

    def scan_txs(self, txs):
        for tx in txs:
            self.scan_tx(tx)

    def sign_tx(self, tx, fixed_length=True):
        if self._mode == MiniWalletMode.RAW_P2PK:
            # for exact fee calculation, create only signatures with fixed size by default (>49.89% probability):
            # 65 bytes: high-R val (33 bytes) + low-S val (32 bytes)
            # with the DER header/skeleton data of 6 bytes added, plus 2 bytes scriptSig overhead
            # (OP_PUSHn and SIGHASH_ALL), this leads to a scriptSig target size of 73 bytes
            tx.vin[0].scriptSig = b''
            while not len(tx.vin[0].scriptSig) == 73:
                tx.vin[0].scriptSig = b''
                sign_input_legacy(tx, 0, self._scriptPubKey, self._priv_key)
                if not fixed_length:
                    break
        elif self._mode == MiniWalletMode.RAW_OP_TRUE:
            for i in tx.vin:
                i.scriptSig = CScript([OP_NOP] * 43)  # pad to identical size
        elif self._mode == MiniWalletMode.ADDRESS_OP_TRUE:
            tx.wit.vtxinwit = [CTxInWitness()] * len(tx.vin)
            for i in tx.wit.vtxinwit:
                i.scriptWitness.stack = [CScript([OP_TRUE]), bytes([LEAF_VERSION_TAPSCRIPT]) + self._internal_key]
        else:
            assert False

    def generate(self, num_blocks, **kwargs):
        """Generate blocks with coinbase outputs to the internal address, and call rescan_utxos"""
        blocks = self._test_node.generatetodescriptor(num_blocks, self.get_descriptor(), **kwargs)
        # Calling rescan_utxos here makes sure that after a generate the utxo
        # set is in a clean state. For example, the wallet will update
        # - if the caller consumed utxos, but never used them
        # - if the caller sent a transaction that is not mined or got rbf'd
        # - after block re-orgs
        # - the utxo height for mined mempool txs
        # - However, the wallet will not consider remaining mempool txs
        self.rescan_utxos()
        return blocks

    def get_scriptPubKey(self):
        return self._scriptPubKey

    def get_descriptor(self):
        return descsum_create(f'raw({self._scriptPubKey.hex()})')

    def get_address(self):
        assert_equal(self._mode, MiniWalletMode.ADDRESS_OP_TRUE)
        return self._address

    def get_utxo(self, *, txid: str = '', vout: Optional[int] = None, mark_as_spent=True, confirmed_only=False, blockhash: Optional[str] = None) -> dict:
        """
        Returns a utxo and marks it as spent (pops it from the internal list)

        Args:
        txid: get the first utxo we find from a specific transaction (can be hex string or int for output hash)
        blockhash: optional block hash that contains the transaction (avoids requiring -txindex)
        """
        self._utxos = sorted(self._utxos, key=lambda k: (k['value'], -k['height']))  # Put the largest utxo last
        blocks_height = self._test_node.getblockchaininfo()['blocks']
        mature_coins = list(filter(lambda utxo: not utxo['coinbase'] or COINBASE_MATURITY - 1 <= blocks_height - utxo['height'], self._utxos))
        if txid:
            # Convert txid to hex string if it's an int (for output hash support)
            if isinstance(txid, int):
                txid = f"{txid:064x}"
            elif isinstance(txid, str):
                # Ensure txid is exactly 64 hex characters (pad with leading zeros if needed)
                # This handles cases where hashes are missing leading zeros
                if len(txid) < 64:
                    txid = txid.zfill(64)
                elif len(txid) > 64:
                    raise ValueError(f"txid must be at most 64 hex characters, got {len(txid)}")
            # First try to find by output hash (txid field in UTXO)
            utxo_filter: Any = filter(lambda utxo: txid == utxo['txid'], self._utxos)
            try:
                utxo = next(utxo_filter)
                index = self._utxos.index(utxo)
            except StopIteration:
                # If not found by output hash, try to find by transaction hash
                # First try to find by transaction_txid field (if UTXOs have it)
                found_utxo = None
                for utxo in self._utxos:
                    if utxo.get('transaction_txid') == txid:
                        found_utxo = utxo
                        index = self._utxos.index(utxo)
                        break
                if found_utxo:
                    utxo = found_utxo
                else:
                    # If not found by transaction_txid, try to look up the transaction
                    # First check if it's in the mempool
                    try:
                        mempool = self._test_node.getrawmempool()
                        if txid in mempool:
                            # Transaction is in mempool, get it
                            tx_details = self._test_node.getrawtransaction(txid, True)
                            # Scan the transaction to add any missing UTXOs
                            self.scan_tx(tx_details)
                            # Find UTXOs from this transaction by matching output hashes
                            for i, output in enumerate(tx_details['vout']):
                                output_hash = output['hash']
                                utxo_filter = filter(lambda utxo: output_hash == utxo['txid'], self._utxos)
                                try:
                                    utxo = next(utxo_filter)
                                    index = self._utxos.index(utxo)
                                    break
                                except StopIteration:
                                    continue
                            else:
                                raise StopIteration(f"No UTXO found with txid={txid}, confirmed_only={confirmed_only}")
                        else:
                            # Transaction is not in mempool, try to get it from blockchain (requires -txindex)
                            try:
                                if blockhash is not None:
                                    tx_details = self._test_node.getrawtransaction(txid, True, blockhash)
                                else:
                                    tx_details = self._test_node.getrawtransaction(txid, True)
                                # Scan the transaction to add any missing UTXOs
                                self.scan_tx(tx_details)
                                # Find UTXOs from this transaction by matching output hashes
                                for i, output in enumerate(tx_details['vout']):
                                    output_hash = output['hash']
                                    utxo_filter = filter(lambda utxo: output_hash == utxo['txid'], self._utxos)
                                    try:
                                        utxo = next(utxo_filter)
                                        index = self._utxos.index(utxo)
                                        break
                                    except StopIteration:
                                        continue
                                else:
                                    raise StopIteration(f"No UTXO found with txid={txid}, confirmed_only={confirmed_only}")
                            except Exception:
                                # Transaction not found in mempool or blockchain
                                raise StopIteration(f"No UTXO found with txid={txid}, confirmed_only={confirmed_only}")
                    except Exception:
                        raise StopIteration(f"No UTXO found with txid={txid}, confirmed_only={confirmed_only}")
        else:
            utxo_filter = reversed(mature_coins)  # By default the largest utxo
            if confirmed_only:
                utxo_filter = filter(lambda utxo: utxo['confirmations'] > 0, utxo_filter)
            try:
                utxo = next(utxo_filter)
                index = self._utxos.index(utxo)
            except StopIteration:
                raise StopIteration(f"No UTXO found with txid={txid}, confirmed_only={confirmed_only}")
        if confirmed_only and utxo['confirmations'] == 0:
            raise StopIteration(f"No UTXO found with txid={txid}, confirmed_only={confirmed_only}")
        if mark_as_spent:
            return self._utxos.pop(index)
        else:
            return self._utxos[index]

    def get_utxos(self, *, include_immature_coinbase=False, mark_as_spent=True, confirmed_only=False):
        """Returns the list of all utxos and optionally mark them as spent"""
        if not include_immature_coinbase:
            blocks_height = self._test_node.getblockchaininfo()['blocks']
            utxo_filter = filter(lambda utxo: not utxo['coinbase'] or COINBASE_MATURITY - 1 <= blocks_height - utxo['height'], self._utxos)
        else:
            utxo_filter = self._utxos
        if confirmed_only:
            utxo_filter = filter(lambda utxo: utxo['confirmations'] > 0, utxo_filter)
        utxos = deepcopy(list(utxo_filter))
        if mark_as_spent:
            self._utxos = []
        return utxos

    def send_self_transfer(self, *, from_node, **kwargs):
        """Call create_self_transfer and send the transaction."""
        tx = self.create_self_transfer(**kwargs)
        self.sendrawtransaction(from_node=from_node, tx_hex=tx['hex'])
        return tx

    def send_to(self, *, from_node, scriptPubKey, amount, fee=1000):
        """
        Create and send a tx with an output to a given scriptPubKey/amount,
        plus a change output to our internal address. To keep things simple, a
        fixed fee given in Satoshi is used.

        Note that this method fails if there is no single internal utxo
        available that can cover the cost for the amount and the fixed fee
        (the utxo with the largest value is taken).
        """
        tx = self.create_self_transfer(fee_rate=0)["tx"]
        assert_greater_than_or_equal(tx.vout[0].nValue, amount + fee)
        tx.vout[0].nValue -= (amount + fee)           # change output -> MiniWallet
        tx.vout.append(CTxOut(amount, scriptPubKey))  # arbitrary output -> to be returned
        txid = self.sendrawtransaction(from_node=from_node, tx_hex=tx.serialize().hex())
        return {
            "sent_vout": 1,
            "txid": hex(tx.vout[1].hash())[2:],
            "txidhash": txid,
            "wtxid": tx.getwtxid(),
            "hex": tx.serialize().hex(),
            "tx": tx,
        }

    def send_self_transfer_multi(self, *, from_node, **kwargs):
        """Call create_self_transfer_multi and send the transaction."""
        tx = self.create_self_transfer_multi(**kwargs)
        self.sendrawtransaction(from_node=from_node, tx_hex=tx["hex"])
        return tx

    def create_self_transfer_multi(
        self,
        *,
        utxos_to_spend: Optional[list[dict]] = None,
        num_outputs=1,
        amount_per_output=0,
        locktime=0,
        sequence=0,
        fee_per_output=1000,
        target_weight=0,
        confirmed_only=False
    ):
        """
        Create and return a transaction that spends the given UTXOs and creates a
        certain number of outputs with equal amounts. The output amounts can be
        set by amount_per_output or automatically calculated with a fee_per_output.
        """
        utxos_to_spend = utxos_to_spend or [self.get_utxo(confirmed_only=confirmed_only)]
        sequence = [sequence] * len(utxos_to_spend) if type(sequence) is int else sequence
        assert_equal(len(utxos_to_spend), len(sequence))

        # calculate output amount
        inputs_value_total = sum([int(COIN * utxo['value']) for utxo in utxos_to_spend])
        outputs_value_total = inputs_value_total - fee_per_output * num_outputs
        amount_per_output = amount_per_output or (outputs_value_total // num_outputs)
        assert amount_per_output > 0
        outputs_value_total = amount_per_output * num_outputs
        fee = Decimal(inputs_value_total - outputs_value_total) / COIN

        # create tx
        tx = CTransaction()
        txins = []
        for utxo_to_spend, seq in zip(utxos_to_spend, sequence):
            prev_hash = utxo_to_spend['txid'] if isinstance(utxo_to_spend['txid'], int) else int(utxo_to_spend['txid'], 16)
            txins.append(CTxIn(COutPoint(prev_hash), nSequence=seq))
        tx.vin = txins
        tx.vout = [CTxOut(amount_per_output, bytearray(self._scriptPubKey)) for _ in range(num_outputs)]
        for i in range(len(tx.vout)):
            tx.vout[i].predicate = random.randbytes(8)
        tx.nLockTime = locktime

        self.sign_tx(tx)

        if target_weight:
            self._bulk_tx(tx, target_weight)

        txid = tx.rehash()
        return {
            "new_utxos": [dict(self._create_utxo(
                txid=tx.vout[i].hash(),
                value=Decimal(tx.vout[i].nValue) / COIN,
                height=0,
                coinbase=False,
                confirmations=0,
            ), transaction_txid=txid) for i in range(len(tx.vout))],
            "fee": fee,
            "txid": txid,
            "wtxid": tx.getwtxid(),
            "hex": tx.serialize().hex(),
            "tx": tx,
        }

    def create_self_transfer(self, *,
            fee_rate=Decimal("0.003"),
            fee=Decimal("0"),
            utxo_to_spend=None,
            locktime=0,
            sequence=0,
            target_weight=0,
            confirmed_only=False
    ):
        """Create and return a tx with the specified fee. If fee is 0, use fee_rate, where the resulting fee may be exact or at most one satoshi higher than needed."""
        utxo_to_spend = utxo_to_spend or self.get_utxo(confirmed_only=confirmed_only)
        assert fee_rate >= 0
        assert fee >= 0
        # calculate fee
        if self._mode in (MiniWalletMode.RAW_OP_TRUE, MiniWalletMode.ADDRESS_OP_TRUE):
            vsize = Decimal(125)  # anyone-can-spend
        elif self._mode == MiniWalletMode.RAW_P2PK:
            vsize = Decimal(189)  # P2PK (73 bytes scriptSig + 35 bytes scriptPubKey + 60 bytes other)
        else:
            assert False
        send_value = utxo_to_spend["value"] - (fee or (fee_rate * vsize / 1000))

        # create tx
        tx = self.create_self_transfer_multi(utxos_to_spend=[utxo_to_spend], locktime=locktime, sequence=sequence, amount_per_output=int(COIN * send_value), target_weight=target_weight)
        if not target_weight:
            assert_equal(tx["tx"].get_vsize(), vsize)
        tx["new_utxo"] = tx.pop("new_utxos")[0]

        return tx

    def sendrawtransaction(self, *, from_node, tx_hex, maxfeerate=0, **kwargs):
        txid = from_node.sendrawtransaction(hexstring=tx_hex, maxfeerate=maxfeerate, **kwargs)
        self.scan_tx(from_node.decoderawtransaction(tx_hex))
        return txid

    def create_self_transfer_chain(self, *, chain_length, utxo_to_spend=None):
        """
        Create a "chain" of chain_length transactions. The nth transaction in
        the chain is a child of the n-1th transaction and parent of the n+1th transaction.
        """
        chaintip_utxo = utxo_to_spend or self.get_utxo()
        chain = []

        for _ in range(chain_length):
            tx = self.create_self_transfer(utxo_to_spend=chaintip_utxo)
            chaintip_utxo = tx["new_utxo"]
            chain.append(tx)

        return chain

    def send_self_transfer_chain(self, *, from_node, **kwargs):
        """Create and send a "chain" of chain_length transactions. The nth transaction in
        the chain is a child of the n-1th transaction and parent of the n+1th transaction.

        Returns a list of objects for each tx (see create_self_transfer_multi).
        """
        chain = self.create_self_transfer_chain(**kwargs)
        for t in chain:
            self.sendrawtransaction(from_node=from_node, tx_hex=t["hex"])
        return chain


def getnewdestination(address_type='bech32m'):
    """Generate a random destination of the specified type and return the
       corresponding public key, scriptPubKey and address. Supported types are
       'legacy', 'p2sh-segwit', 'bech32' and 'bech32m'. Can be used when a random
       destination is needed, but no compiled wallet is available (e.g. as
       replacement to the getnewaddress/getaddressinfo RPCs)."""
    key, pubkey = generate_keypair()
    if address_type == 'legacy':
        scriptpubkey = key_to_p2pkh_script(pubkey)
        address = key_to_p2pkh(pubkey)
    elif address_type == 'p2sh-segwit':
        scriptpubkey = key_to_p2sh_p2wpkh_script(pubkey)
        address = key_to_p2sh_p2wpkh(pubkey)
    elif address_type == 'bech32':
        scriptpubkey = key_to_p2wpkh_script(pubkey)
        address = key_to_p2wpkh(pubkey)
    elif address_type == 'bech32m':
        tap = taproot_construct(compute_xonly_pubkey(key.get_bytes())[0])
        pubkey = tap.output_pubkey
        scriptpubkey = tap.scriptPubKey
        address = output_key_to_p2tr(pubkey)
    else:
        assert False
    return pubkey, scriptpubkey, address
