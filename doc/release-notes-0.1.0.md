Navio Core version 0.1.0 Release Notes
======================================

Navio Core version 0.1.0 is now available from:

  <https://github.com/nav-io/navio-core/releases/tag/v0.1.0>

This is the first stable release of Navio Core and the launch of the Navio
mainnet. It is built on the Bitcoin Core codebase with BLSCT (Boneh-Lynn-Shacham
Confidential Transactions) for private, confidential transfers.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/nav-io/navio-core/issues>

Mainnet Launch
==============

This release activates the Navio mainnet. The mainnet genesis block was mined
for this launch:

  - Genesis hash:   `0af3c23ae1ac4910693b7187ac61641d16d1cf49cba7acf8649d48e831d86b13`
  - Merkle root:    `96f8dfcc3c433012bc9d4b42e85fe543936609f87fce2cc9d5484383ee2f9aaf`
  - Timestamp:      2026-07-01 13:00:00 UTC (`1782910800`)

The genesis coinbase is a plain unspendable `OP_RETURN` output (the genesis
block is never connected to the UTXO set). A hidden message is embedded in the
coinbase scriptSig — decode the genesis block to find it.

How to Install
==============

Download the binaries for your platform and run the installer (Windows), copy
`Navio-Qt` to `/Applications` (macOS), or copy `naviod`/`navio-qt` into your
path (Linux).

Verify the signed checksums in `SHA256SUMS` / `SHA256SUMS.asc` before running.

Compatibility
=============

Navio Core is supported and tested on operating systems using the Linux Kernel
3.17+, macOS 11.0+, and Windows 7 and newer. Other Unix-like systems may work
but are not regularly tested.

Notable changes
===============

- BLSCT confidential transactions: confidential amounts and stealth
  (`nav1...`) subaddresses.
- BLSCT staking support.
- Network parameters finalized for mainnet launch (message start, default port
  48470, address prefixes, `nav` bech32 modifier HRP for BLSCT addresses).

Credits
=======

Thanks to everyone who contributed to this release, and to the Bitcoin Core
developers whose work Navio Core is built upon.
