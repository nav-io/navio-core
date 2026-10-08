#!/usr/bin/env python3
# Copyright (c) 2026 The Navio developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the -i2pd router supervisor against a stub router (-i2pdcmd).

The stub is a shell script that records each launch (pid and arguments) and
how it was stopped, so the test can check that naviod starts the router with
the expected arguments, restarts it after it dies, asks it to stop on shutdown,
and kills it when it ignores that request.
"""

import os
import signal
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
)

STUB_ROUTER = """#!/bin/sh
dir=$(dirname "$0")
echo "$$ $*" >> "$dir/launches"
if [ "$(cat "$dir/mode")" = ignore-term ]; then
    trap '' TERM
else
    trap 'echo "$$" >> "$dir/terms"; exit 0' TERM
fi
while :; do sleep 1; done
"""


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class I2PDSupervisorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_i2pd()
        # The stub router is a shell script.
        self.skip_if_platform_not_posix()

    def launches(self):
        path = self.stub_dir / 'launches'
        if not path.exists():
            return []
        return [line.split(' ', 1) for line in path.read_text(encoding='utf-8').splitlines()]

    def terms(self):
        path = self.stub_dir / 'terms'
        return path.read_text(encoding='utf-8').split() if path.exists() else []

    def set_mode(self, mode):
        (self.stub_dir / 'mode').write_text(mode, encoding='utf-8')

    def run_test(self):
        node = self.nodes[0]
        self.stub_dir = Path(self.options.tmpdir) / 'stub'
        self.stub_dir.mkdir()
        stub = self.stub_dir / 'i2pd'
        stub.write_text(STUB_ROUTER, encoding='utf-8')
        stub.chmod(0o755)
        self.set_mode('run')
        # A port reserved for this test that nothing listens on.
        sam_port = p2p_port(1)
        args = ['-i2pd=1', f'-i2pdcmd={stub}', f'-i2pdsamport={sam_port}', '-i2pacceptincoming=0']

        self.log.info("Start the router with the expected arguments")
        self.restart_node(0, extra_args=args)
        self.wait_until(lambda: len(self.launches()) == 1)
        pid, argline = self.launches()[0]
        pid = int(pid)
        assert pid_alive(pid)
        router_dir = node.chain_path / 'i2pd'
        for expected in [
            f'--datadir={router_dir}',
            '--sam.enabled=true',
            '--sam.address=127.0.0.1',
            f'--sam.port={sam_port}',
            '--http.enabled=false',
            '--httpproxy.enabled=false',
            '--socksproxy.enabled=false',
            '--reseed.verify=true',
            '--notransit',
            f'--logfile={router_dir / "i2pd.log"}',
        ]:
            assert expected in argline.split(' '), f"{expected} missing from {argline}"

        self.log.info("Restart the router after it dies")
        with node.assert_debug_log(['i2pd: router exited; restarting in 1000 ms', 'i2pd: started router'], timeout=10):
            os.kill(pid, signal.SIGKILL)
            self.wait_until(lambda: len(self.launches()) == 2)
        new_pid = int(self.launches()[1][0])
        assert new_pid != pid
        assert pid_alive(new_pid)

        self.log.info("Ask the router to stop on shutdown")
        self.stop_node(0)
        self.wait_until(lambda: not pid_alive(new_pid))
        assert_equal(self.terms(), [str(new_pid)])
        assert_equal(len(self.launches()), 2)

        self.log.info("Kill a router that ignores the request to stop")
        self.set_mode('ignore-term')
        self.start_node(0, extra_args=args)
        self.wait_until(lambda: len(self.launches()) == 3)
        stubborn_pid = int(self.launches()[2][0])
        started = time.time()
        with node.assert_debug_log(['i2pd: router did not exit within 10 seconds; killing it']):
            self.stop_node(0)
        assert not pid_alive(stubborn_pid)
        assert time.time() - started >= 10
        assert_equal(self.terms(), [str(new_pid)])


if __name__ == '__main__':
    I2PDSupervisorTest(__file__).main()
