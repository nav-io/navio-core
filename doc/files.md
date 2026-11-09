# Navio file system

**Contents**

- [Data directory location](#data-directory-location)

- [Data directory layout](#data-directory-layout)

- [Multi-wallet environment](#multi-wallet-environment)

- [Notes](#notes)

## Data directory location

The data directory is the default location where the Navio files are stored.

1. The default data directory paths for supported platforms are:

| Platform | Data directory path                           |
| -------- | --------------------------------------------- |
| Linux    | `$HOME/.navio/`                               |
| macOS    | `$HOME/Library/Application Support/Navio/`    |
| Windows  | `%APPDATA%\Navio\` <sup>[\[1\]](#note1)</sup> |

2. A custom data directory path can be specified with the `-datadir` option.

3. All content of the data directory, except for `navio.conf` file, is
   chain-specific. This means the actual data directory paths for non-mainnet
   cases differ:

| Chain option                             | Data directory path               |
| ---------------------------------------- | --------------------------------- |
| `-chain=main` (default)                  | _path_to_datadir_`/`              |
| `-chain=test` or `-testnet`              | _path_to_datadir_`/testnet7/`     |
| `-chain=signet` or `-signet`             | _path_to_datadir_`/signet/`       |
| `-chain=regtest` or `-regtest`           | _path_to_datadir_`/regtest/`      |
| `-chain=blsctregtest` or `-blsctregtest` | _path_to_datadir_`/blsctregtest/` |

## Data directory layout

| Subdirectory                    | File(s)                                   | Description                                                                                                                                                                                                                                                            |
| ------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `blocks/`                       |                                           | Blocks directory; can be specified by `-blocksdir` option (except for `blocks/index/`)                                                                                                                                                                                 |
| `blocks/index/`                 | LevelDB database                          | Block index; `-blocksdir` option does not affect this path                                                                                                                                                                                                             |
| `blocks/`                       | `blkNNNNN.dat`<sup>[\[2\]](#note2)</sup>  | Actual Navio blocks (in network format, dumped in raw on disk, 128 MiB per file)                                                                                                                                                                                       |
| `blocks/`                       | `revNNNNN.dat`<sup>[\[2\]](#note2)</sup>  | Block undo data (custom format)                                                                                                                                                                                                                                        |
| `chainstate/`                   | LevelDB database                          | Blockchain state (a compact representation of all currently unspent transaction outputs (UTXOs) and metadata about the transactions they are from)                                                                                                                     |
| `indexes/txindex/`              | LevelDB database                          | Transaction index; _optional_, used if `-txindex=1`                                                                                                                                                                                                                    |
| `indexes/outindex/`             | LevelDB database                          | Output index; _optional_, used if `-outindex=1`                                                                                                                                                                                                                        |
| `indexes/blockfilter/basic/db/` | LevelDB database                          | Blockfilter index LevelDB database for the basic filtertype; _optional_, used if `-blockfilterindex=basic`                                                                                                                                                             |
| `indexes/blockfilter/basic/`    | `fltrNNNNN.dat`<sup>[\[2\]](#note2)</sup> | Blockfilter index filters for the basic filtertype; _optional_, used if `-blockfilterindex=basic`                                                                                                                                                                      |
| `indexes/coinstats/db/`         | LevelDB database                          | Coinstats index; _optional_, used if `-coinstatsindex=1`                                                                                                                                                                                                               |
| `p2pmsg_inbox/`                 | LevelDB database                          | Store of received p2p messages, drained by the `listp2pmsgs` RPC; size and expiry are bounded by `-p2pmsgstoresize` and `-p2pmsgstoreexpiry`; not created when `-p2pmsgstoresize=0` or `-p2pmsg=0`                                                                     |
| `p2pmsg_archive/`               | LevelDB database                          | Archive of relayed, flagged p2p message envelopes kept so offline peers can retrieve them later; _optional_, used if `-p2pmsgarchive=1`                                                                                                                                |
| `wallets/`                      |                                           | [Contains wallets](#multi-wallet-environment); can be specified by `-walletdir` option; if `wallets/` subdirectory does not exist, wallets reside in the [data directory](#data-directory-location)                                                                    |
| `./`                            | `anchors.dat`                             | Anchor IP address database, created on shutdown and deleted at startup. Anchors are last known outgoing block-relay-only peers that are tried to re-connect to on startup                                                                                              |
| `./`                            | `banlist.json`                            | Stores the addresses/subnets of banned nodes.                                                                                                                                                                                                                          |
| `./`                            | `navio.conf`                              | User-defined [configuration settings](navio-conf.md) for `naviod`. File is not written to by the software and must be created manually. Path can be specified by `-conf` option                                                                                        |
| `./`                            | `naviod.pid`                              | Stores the process ID (PID) of `naviod` while running; created at start and deleted on shutdown; can be specified by `-pid` option                                                                                                                                     |
| `./`                            | `debug.log`                               | Contains debug information and general logging generated by `naviod`; can be specified by `-debuglogfile` option                                                                                                                                                       |
| `./`                            | `fee_estimates.dat`                       | Stores statistics used to estimate minimum transaction fees required for confirmation                                                                                                                                                                                  |
| `./`                            | `ip_asn.map`                              | IP addresses to Autonomous System Numbers (ASNs) mapping used for bucketing of the peers; path can be specified with the `-asmap` option                                                                                                                               |
| `./`                            | `mempool.dat`                             | Dump of the mempool's transactions                                                                                                                                                                                                                                     |
| `./`                            | `onion_v3_private_key`                    | Cached Tor onion service private key for `-listenonion` option                                                                                                                                                                                                         |
| `./`                            | `i2p_private_key`                         | Private key that corresponds to our I2P address. When `-i2psam=` is specified the contents of this file is used to identify ourselves for making outgoing connections to I2P peers and possibly accepting incoming ones. Automatically generated if it does not exist. |
| `./`                            | `p2pmsg_identity.dat`                     | Private key of this node's p2p messaging identity; _optional_, only written if `-p2pmsgpersistidentity=1` (otherwise the identity is ephemeral per run). Created with owner-only permissions                                                                           |
| `./`                            | `peers.dat`                               | Peer IP address database (custom format)                                                                                                                                                                                                                               |
| `./`                            | `settings.json`                           | Read-write settings set through RPC interfaces, augmenting manual settings from [navio.conf](navio-conf.md). File is created automatically if read-write settings storage is not disabled with `-nosettings` option. Path can be specified with `-settings` option     |
| `./`                            | `.cookie`                                 | Session RPC authentication cookie; if used, created at start and deleted on shutdown; can be specified by `-rpccookiefile` option                                                                                                                                      |
| `./`                            | `.lock`                                   | Data directory lock file                                                                                                                                                                                                                                               |

## Multi-wallet environment

Wallets are SQLite databases.

1. Each user-defined wallet named "wallet_name" resides in the
   `wallets/wallet_name/` subdirectory.

2. The default (unnamed) wallet resides in `wallets/` subdirectory; if the
   latter does not exist, the wallet resides in the data directory.

3. A wallet database path can be specified with the `-wallet` option.

4. `wallet.dat` files must not be shared across different node instances, as
   that can result in key-reuse and double-spends due the lack of
   synchronization between instances.

5. Any copy or backup of the wallet should be done through a `backupwallet` call
   in order to update and lock the wallet, preventing any file corruption caused
   by updates during the copy.

| Subdirectory | File                 | Description                                                                                                                                              |
| ------------ | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `./`         | `wallet.dat`         | Personal wallet (a SQLite database) with keys and transactions                                                                                           |
| `./`         | `wallet.dat-journal` | SQLite Rollback Journal file for `wallet.dat`. Usually created at start and deleted on shutdown. A user _must keep it as safe_ as the `wallet.dat` file. |

## Notes

<a name="note1">1</a>. The `/` (slash, U+002F) is used as the
platform-independent path component separator in this document.

<a name="note2">2</a>. `NNNNN` matches `[0-9]{5}` regex.
