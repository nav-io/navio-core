#!/usr/bin/env python3
# Copyright (c) 2020-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test that the proper port is used for -externalip=
"""

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

# We need to bind to a routable address for this test to exercise the relevant code.
# To set a routable address on the machine use:
# Linux:
# ifconfig lo:0 1.1.1.1/32 up  # to set up
# ifconfig lo:0 down  # to remove it, after the test
# FreeBSD:
# ifconfig lo0 1.1.1.1/32 alias  # to set up
# ifconfig lo0 1.1.1.1 -alias  # to remove it, after the test
ADDR = '1.1.1.1'

# array of tuples [arguments, expected port in localaddresses]
# The fixed ports sit above rpc_port()'s block at the default PORT_MIN, below
# the ephemeral range, and clear of feature_bind_port_discover's BIND_PORT.
EXPECTED = [
    [['-externalip=2.2.2.2',       '-port=31101'],                        31101],
    [['-externalip=2.2.2.2',       '-port=31102', f'-bind={ADDR}'],       31102],
    [['-externalip=2.2.2.2',                      f'-bind={ADDR}'],       'default_p2p_port'],
    [['-externalip=2.2.2.2',       '-port=31103', f'-bind={ADDR}:31104'], 31104],
    [['-externalip=2.2.2.2',                      f'-bind={ADDR}:31105'], 31105],
    [['-externalip=2.2.2.2:31106', '-port=31107'],                        31106],
    [['-externalip=2.2.2.2:31108', '-port=31109', f'-bind={ADDR}'],       31108],
    [['-externalip=2.2.2.2:31110',                f'-bind={ADDR}'],       31110],
    [['-externalip=2.2.2.2:31111', '-port=31112', f'-bind={ADDR}:31113'], 31111],
    [['-externalip=2.2.2.2:31114',                f'-bind={ADDR}:31115'], 31114],
    [['-externalip=2.2.2.2',       '-port=31116', f'-bind={ADDR}:31117',
                                             f'-whitebind={ADDR}:31118'], 31117],
    [['-externalip=2.2.2.2',       '-port=31119',
                                             f'-whitebind={ADDR}:31120'], 31120],
]

class BindPortExternalIPTest(BitcoinTestFramework):
    def set_test_params(self):
        # Avoid any -bind= on the command line. Force the framework to avoid adding -bind=127.0.0.1.
        self.setup_clean_chain = True
        self.bind_to_localhost_only = False
        self.num_nodes = len(EXPECTED)
        self.extra_args = list(map(lambda e: e[0], EXPECTED))

    def add_options(self, parser):
        parser.add_argument(
            "--ihave1111", action='store_true', dest="ihave1111",
            help=f"Run the test, assuming {ADDR} is configured on the machine",
            default=False)

    def skip_test_if_missing_module(self):
        if not self.options.ihave1111:
            raise SkipTest(
                f"To run this test make sure that {ADDR} (a routable address) is assigned "
                "to one of the interfaces on this machine and rerun with --ihave1111")

    def run_test(self):
        self.log.info("Test the proper port is used for -externalip=")
        for i in range(len(EXPECTED)):
            expected_port = EXPECTED[i][1]
            if expected_port == 'default_p2p_port':
                expected_port = p2p_port(i)
            found = False
            for local in self.nodes[i].getnetworkinfo()['localaddresses']:
                if local['address'] == '2.2.2.2':
                    assert_equal(local['port'], expected_port)
                    found = True
                    break
            assert found

if __name__ == '__main__':
    BindPortExternalIPTest(__file__).main()
