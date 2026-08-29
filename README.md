Navio Core integration/staging tree
=====================================

Navio Core is a fork of [Bitcoin Core](https://github.com/bitcoin/bitcoin). This
repository hosts the source code for Navio Core, the reference implementation of
the Navio protocol, whose mainnet runs confidential BLSCT transactions and
Proof-of-Private-Stake consensus.

https://nav.io

For an immediately usable, binary version of the Navio Core software, see
https://nav.io/get-started.

Further information about Navio Core is available in the [doc folder](/doc),
the [wiki](https://github.com/nav-io/navio-core/wiki) and the [documentation website](https://docs.nav.io).

What is Navio?
----------------

Navio is an experimental digital currency that enables privacy-enhanced payments to
anyone, anywhere in the world. Navio uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network using a private proof of stake protocol. Navio
Core is the name of open source software which enables the use of this currency.

License
-------

Navio Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built (see `doc/build-*.md` for instructions) and tested, but it is not guaranteed to be
completely stable. [Tags](https://github.com/navocin/navio/tags) are created
regularly from release branches to indicate new official, stable release versions of Navio Core.

Building from sources
---------------------

Platform-specific instructions live in [`doc/build-*.md`](/doc).

The BLS12-381 arithmetic behind BLSCT comes from the vendored
[supranational/blst](https://github.com/supranational/blst) (`src/blst`),
built by CMake with no extra dependencies. On x86_64 both the ADX and the
non-ADX code paths are compiled and selected at runtime (`BLST_PORTABLE=ON`,
the default); other architectures use blst's portable C implementation.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled with `-DBUILD_TESTS=OFF`) with: `ctest --test-dir build`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The CI (Continuous Integration) systems make sure that every pull request is built for Windows, Linux, and macOS,
and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

