# Navio Core

## Setup

Navio Core is the reference implementation of the Navio protocol. It downloads
and, by default, stores the entire history of the Navio chain. Depending on the
speed of your computer and network connection, the synchronization process can
take anywhere from a few minutes to a few hours.

To download Navio Core, visit [nav.io/get-started](https://nav.io/get-started)
or the [GitHub releases](https://github.com/nav-io/navio-core/releases).

## Running

Navio Core has no GUI. Unpack the files into a directory and run `bin/naviod`
(`bin/naviod.exe` on Windows) to start the node, and `bin/navio-cli` to talk to
it.

### Need Help?

- See the [documentation website](https://docs.nav.io) and the
  [wiki](https://github.com/nav-io/navio-core/wiki).
- Report bugs on the
  [issue tracker](https://github.com/nav-io/navio-core/issues).

## Building

The following are developer notes on how to build Navio Core on your native
platform. They are not complete guides, but include notes on the necessary
libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)
- [Android Build Notes](build-android.md)

## Development

The Navio repo's [root README](/README.md) contains relevant information on the
development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Process](release-process.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Navio features

- [Cold Staking](cold-staking.md)
- [BLSCT Cold Signing](blsct-cold-signing.md)
- [Encrypted P2P Messaging](p2p-encrypted-messaging.md)
- [bech32_mod Generator Polynomial](bech32-mod-gen-poly.md)

### Miscellaneous

- [Assets Attribution](assets-attribution.md)
- [navio.conf Configuration File](navio-conf.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [Managing Wallets](managing-wallets.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

## License

Distributed under the [MIT software license](/COPYING).
