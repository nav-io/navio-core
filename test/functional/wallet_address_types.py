#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the wallet can send and receive using all combinations of address types.

There are 5 nodes-under-test:
    - node0 uses legacy addresses
    - node1 uses p2sh/segwit addresses
    - node2 uses p2sh/segwit addresses and bech32 addresses for change
    - node3 uses bech32 addresses
    - node4 uses a p2sh/segwit addresses for change

node5 exists to generate new blocks.

## Sending to address types test

A series of tests, iterating over node0-node3. In each iteration of the test, one node sends:
    - 10/101th of its balance to itself (using getrawchangeaddress)
    - 20/101th to the next node
    - 30/101th to the node after that
    - 40/101th to the remaining node
    - 1/101th remains as fee+change

Repeat test, but with explicit address_type parameters passed to getnewaddress
and getrawchangeaddress:
    - node0 and node3 send to p2sh.
    - node1 sends to bech32.
    - node2 sends to legacy.

As every node sends coins after receiving, this also
verifies that spending coins sent to all these address types works.

## Change type test

Test that the nodes generate the correct change address type:
    - node0 always uses a legacy change address.
    - node1 uses a bech32 addresses for change if any destination address is bech32.
    - node2 always uses a bech32 address for change
    - node3 always uses a bech32 address for change
    - node4 always uses p2sh/segwit output for change.

Descriptor wallets also make bech32m addresses.
"""

from decimal import Decimal
import itertools

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.descriptors import (
    descsum_create,
    descsum_check,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

class AddressTypeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 6
        self.extra_args = [
            ["-addresstype=legacy"],
            ["-addresstype=p2sh-segwit"],
            ["-addresstype=p2sh-segwit", "-changetype=bech32"],
            ["-addresstype=bech32"],
            ["-changetype=p2sh-segwit", "-addresstype=bech32"],
            [],
        ]
        # whitelist all peers to speed up tx relay / mempool sync
        for args in self.extra_args:
            args.append("-whitelist=noban@127.0.0.1")
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

        # Fully mesh-connect nodes for faster mempool sync
        for i, j in itertools.product(range(self.num_nodes), repeat=2):
            if i > j:
                self.connect_nodes(i, j)
        self.sync_all()

    def get_balances(self, key='trusted'):
        """Return a list of balances."""
        return [self.nodes[i].getbalances()['mine'][key] for i in range(4)]

    def test_address(self, node, address, typ):
        """Run sanity checks on an address."""
        info = self.nodes[node].getaddressinfo(address)
        assert self.nodes[node].validateaddress(address)['isvalid']
        assert_equal(info.get('solvable'), True)

        if typ == 'legacy':
            # P2PKH
            assert not info['isscript']
            assert not info['iswitness']
            assert 'pubkey' in info
        elif typ == 'p2sh-segwit':
            # P2SH-P2WPKH
            assert info['isscript']
            assert not info['iswitness']
            assert_equal(info['script'], 'witness_v0_keyhash')
            assert 'pubkey' in info
        elif typ == 'bech32':
            # P2WPKH
            assert not info['isscript']
            assert info['iswitness']
            assert_equal(info['witness_version'], 0)
            assert_equal(len(info['witness_program']), 40)
            assert 'pubkey' in info
        elif typ == "bech32m":
            # P2TR single sig
            assert info["isscript"]
            assert info["iswitness"]
            assert_equal(info["witness_version"], 1)
            assert_equal(len(info["witness_program"]), 64)
        else:
            # Unknown type
            assert False

    def test_desc(self, node, address, typ, utxo):
        """Run sanity checks on a descriptor reported by getaddressinfo."""
        info = self.nodes[node].getaddressinfo(address)
        assert 'desc' in info
        assert_equal(info['desc'], utxo['desc'])
        assert self.nodes[node].validateaddress(address)['isvalid']

        # Find the key origin info of each key through getaddressinfo, which
        # tests consistency between the reported fingerprints/paths and the
        # descriptor logic.
        def key_desc(key_info):
            assert_equal(len(key_info['hdmasterfingerprint']), 8)
            assert_equal(key_info['hdkeypath'][0], 'm')
            return '[' + key_info['hdmasterfingerprint'] + key_info['hdkeypath'][1:].replace("'", "h") + ']' + key_info['pubkey']

        key_descs = {info['pubkey']: key_desc(info)}

        # Verify the descriptor checksum against the Python implementation
        assert descsum_check(info['desc'])
        # Verify that stripping the checksum and recreating it using Python roundtrips
        assert info['desc'] == descsum_create(info['desc'][:-9])
        # Verify that stripping the checksum and feeding it to getdescriptorinfo roundtrips
        assert info['desc'] == self.nodes[0].getdescriptorinfo(info['desc'][:-9])['descriptor']
        assert_equal(info['desc'][-8:], self.nodes[0].getdescriptorinfo(info['desc'][:-9])['checksum'])
        # Verify that keeping the checksum and feeding it to getdescriptorinfo roundtrips
        assert info['desc'] == self.nodes[0].getdescriptorinfo(info['desc'])['descriptor']
        assert_equal(info['desc'][-8:], self.nodes[0].getdescriptorinfo(info['desc'])['checksum'])

        if typ == 'legacy':
            # P2PKH
            assert_equal(info['desc'], descsum_create("pkh(%s)" % key_descs[info['pubkey']]))
        elif typ == 'p2sh-segwit':
            # P2SH-P2WPKH
            assert_equal(info['desc'], descsum_create("sh(wpkh(%s))" % key_descs[info['pubkey']]))
        elif typ == 'bech32':
            # P2WPKH
            assert_equal(info['desc'], descsum_create("wpkh(%s)" % key_descs[info['pubkey']]))
        else:
            # Unknown type
            assert False

    def test_change_output_type(self, node_sender, destinations, expected_type):
        txid = self.nodes[node_sender].sendmany(dummy="", amounts=dict.fromkeys(destinations, 0.001))
        tx = self.nodes[node_sender].gettransaction(txid=txid, verbose=True)['decoded']

        # Make sure the transaction has change:
        assert_equal(len(tx["vout"]), len(destinations) + 1)

        # Make sure the destinations are included, and remove them:
        output_addresses = [vout['scriptPubKey']['address'] for vout in tx["vout"]]
        change_addresses = [d for d in output_addresses if d not in destinations]
        assert_equal(len(change_addresses), 1)

        self.log.debug("Check if change address " + change_addresses[0] + " is " + expected_type)
        self.test_address(node_sender, change_addresses[0], typ=expected_type)

    def run_test(self):
        # Mine 101 blocks on node5 to bring nodes out of IBD and make sure that
        # no coinbases are maturing for the nodes-under-test during the test
        self.generate(self.nodes[5], COINBASE_MATURITY + 1)

        compressed_1 = "0296b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52"
        compressed_2 = "037211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073"

        for explicit_type, from_node in itertools.product([False, True], range(4)):
            address_type = None
            if explicit_type:
                if from_node == 1:
                    address_type = 'bech32'
                elif from_node == 0 or from_node == 3:
                    address_type = 'p2sh-segwit'
                else:
                    address_type = 'legacy'
            self.log.info("Sending from node {} ({}) using {}".format(from_node, self.extra_args[from_node], "default" if address_type is None else address_type))
            old_balances = self.get_balances()
            self.log.debug("Old balances are {}".format(old_balances))
            to_send = (old_balances[from_node] / (COINBASE_MATURITY + 1)).quantize(Decimal("0.00000001"))
            sends = {}
            addresses = {}

            self.log.debug("Prepare sends")
            for n, to_node in enumerate(range(from_node, from_node + 4)):
                to_node %= 4
                change = False
                if from_node == to_node:
                    # When sending to self, use getrawchangeaddress
                    address = self.nodes[to_node].getrawchangeaddress(address_type=address_type)
                    change = True
                else:
                    address = self.nodes[to_node].getnewaddress(address_type=address_type)

                # Do some sanity checking on the created address
                if address_type is not None:
                    typ = address_type
                elif to_node == 0:
                    typ = 'legacy'
                elif to_node == 1 or (to_node == 2 and not change):
                    typ = 'p2sh-segwit'
                else:
                    typ = 'bech32'
                self.test_address(to_node, address, typ)

                # Output entry
                sends[address] = to_send * 10 * (1 + n)
                addresses[to_node] = (address, typ)

            self.log.debug("Sending: {}".format(sends))
            self.nodes[from_node].sendmany("", sends)
            self.sync_mempools()

            unconf_balances = self.get_balances('untrusted_pending')
            self.log.debug("Check unconfirmed balances: {}".format(unconf_balances))
            assert_equal(unconf_balances[from_node], 0)
            for n, to_node in enumerate(range(from_node + 1, from_node + 4)):
                to_node %= 4
                assert_equal(unconf_balances[to_node], to_send * 10 * (2 + n))

            # node5 collects fee and block subsidy to keep accounting simple
            self.generate(self.nodes[5], 1)

            # Verify that the receiving wallet contains a UTXO with the expected address, and expected descriptor
            for n, to_node in enumerate(range(from_node, from_node + 4)):
                to_node %= 4
                found = False
                for utxo in self.nodes[to_node].listunspent():
                    if utxo['address'] == addresses[to_node][0]:
                        found = True
                        self.test_desc(to_node, addresses[to_node][0], addresses[to_node][1], utxo)
                        break
                assert found

            new_balances = self.get_balances()
            self.log.debug("Check new balances: {}".format(new_balances))
            # We don't know what fee was set, so we can only check bounds on the balance of the sending node
            assert_greater_than(new_balances[from_node], to_send * 10)
            assert_greater_than(to_send * 11, new_balances[from_node])
            for n, to_node in enumerate(range(from_node + 1, from_node + 4)):
                to_node %= 4
                assert_equal(new_balances[to_node], old_balances[to_node] + to_send * 10 * (2 + n))

        # Get one p2sh/segwit address from node2 and two bech32 addresses from node3:
        to_address_p2sh = self.nodes[2].getnewaddress()
        to_address_bech32_1 = self.nodes[3].getnewaddress()
        to_address_bech32_2 = self.nodes[3].getnewaddress()

        # Fund node 4:
        self.nodes[5].sendtoaddress(self.nodes[4].getnewaddress(), Decimal("1"))
        self.generate(self.nodes[5], 1)
        assert_equal(self.nodes[4].getbalance(), 1)

        self.log.info("Nodes with addresstype=legacy never use a P2WPKH change output (unless changetype is set otherwise):")
        self.test_change_output_type(0, [to_address_bech32_1], 'legacy')

        self.log.info("Nodes with addresstype=p2sh-segwit match the change output")
        self.test_change_output_type(1, [to_address_p2sh], 'p2sh-segwit')
        self.test_change_output_type(1, [to_address_bech32_1], 'bech32')
        self.test_change_output_type(1, [to_address_p2sh, to_address_bech32_1], 'bech32')
        self.test_change_output_type(1, [to_address_bech32_1, to_address_bech32_2], 'bech32')

        self.log.info("Nodes with change_type=bech32 always use a P2WPKH change output:")
        self.test_change_output_type(2, [to_address_bech32_1], 'bech32')
        self.test_change_output_type(2, [to_address_p2sh], 'bech32')

        self.log.info("Nodes with addresstype=bech32 match the change output (unless changetype is set otherwise):")
        self.test_change_output_type(3, [to_address_bech32_1], 'bech32')
        self.test_change_output_type(3, [to_address_p2sh], 'p2sh-segwit')

        self.log.info('getrawchangeaddress defaults to addresstype if -changetype is not set and argument is absent')
        self.test_address(3, self.nodes[3].getrawchangeaddress(), typ='bech32')

        self.log.info('test invalid address type arguments')
        assert_raises_rpc_error(-5, "Unknown address type ''", self.nodes[3].addmultisigaddress, 2, [compressed_1, compressed_2], None, '')
        assert_raises_rpc_error(-5, "Unknown address type ''", self.nodes[3].getnewaddress, None, '')
        assert_raises_rpc_error(-5, "Unknown address type ''", self.nodes[3].getrawchangeaddress, '')
        assert_raises_rpc_error(-5, "Unknown address type 'bech23'", self.nodes[3].getrawchangeaddress, 'bech23')

        self.log.info("Nodes with changetype=p2sh-segwit never use a P2WPKH change output")
        self.test_change_output_type(4, [to_address_bech32_1], 'p2sh-segwit')
        self.test_address(4, self.nodes[4].getrawchangeaddress(), typ='p2sh-segwit')
        self.log.info("Except for getrawchangeaddress if specified:")
        self.test_address(4, self.nodes[4].getrawchangeaddress(), typ='p2sh-segwit')
        self.test_address(4, self.nodes[4].getrawchangeaddress('bech32'), typ='bech32')

        self.log.info("Descriptor wallets have bech32m addresses")
        self.test_address(4, self.nodes[4].getnewaddress("", "bech32m"), typ="bech32m")
        self.test_address(4, self.nodes[4].getrawchangeaddress("bech32m"), typ="bech32m")

        self.test_legacy_dumpwallet_unsupported_addresstype()

    def test_legacy_dumpwallet_unsupported_addresstype(self):
        """A legacy wallet's dumpwallet names an address for every key that has
        no address book entry, derived from -addresstype. None of bech32m,
        blsct or blsct-stake describes an address for a legacy key, so the
        dump must still print a transparent one rather than abort the node or
        leave it blank."""
        for address_type in ["bech32m", "blsct", "blsct-stake"]:
            self.log.info(f"dumpwallet on a legacy wallet with -addresstype={address_type}")
            self.restart_node(5, extra_args=[f"-addresstype={address_type}"])
            wallet_name = f"legacy_dump_{address_type}"
            self.nodes[5].createwallet(wallet_name=wallet_name, descriptors=False, blsct=False)
            wallet = self.nodes[5].get_wallet_rpc(wallet_name)
            dump_path = self.nodes[5].datadir_path / f"{wallet_name}.dump"
            wallet.dumpwallet(dump_path)

            with open(dump_path, encoding="utf8") as f:
                key_lines = [line for line in f if " # addr=" in line and "script=1" not in line]
            # The seed and the keypool keys have no address book entry.
            assert any("hdseed=1" in line for line in key_lines)
            assert any("reserve=1" in line for line in key_lines)
            for line in key_lines:
                addr = line.split(" # addr=")[1].split(" ")[0].strip()
                assert addr, f"empty address in dump line: {line}"
                assert_equal(wallet.getaddressinfo(addr)["ismine"], True)
                info = self.nodes[5].validateaddress(addr)
                assert_equal(info["iswitness"], True)
                assert_equal(info["witness_version"], 0)

if __name__ == '__main__':
    AddressTypeTest(__file__).main()
