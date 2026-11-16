# Managing the Wallet

## 1. Backing Up and Restoring The Wallet

### 1.1 Creating the Wallet

Navio does not create a default wallet. Wallets can be created with the
`createwallet` RPC.

The following command, for example, creates a BLSCT wallet, navio's default and
standard wallet type. Pass `blsct=false` to create a descriptor wallet instead.
More information about this command may be found by running
`navio-cli help createwallet`.

```
$ navio-cli createwallet "wallet-01"
```

By default, wallets are created in the `wallets` folder of the data directory,
which varies by operating system, as shown below. The user can change the
default by using the `-datadir` or `-walletdir` initialization parameters.

| Operating System | Default wallet directory                                  |
| ---------------- | :-------------------------------------------------------- |
| Linux            | `/home/<user>/.navio/wallets`                             |
| Windows          | `C:\Users\<user>\AppData\Roaming\Navio\wallets`           |
| macOS            | `/Users/<user>/Library/Application Support/Navio/wallets` |

### 1.2 Encrypting the Wallet

The `wallet.dat` file is not encrypted by default and is, therefore, vulnerable
if an attacker gains access to the device where the wallet or the backups are
stored.

Wallet encryption may prevent unauthorized access. However, this significantly
increases the risk of losing coins due to forgotten passphrases. There is no way
to recover a passphrase. This tradeoff should be well thought out by the user.

Wallet encryption may also not protect against more sophisticated attacks. An
attacker can, for example, obtain the password by installing a keylogger on the
user's machine.

After encrypting the wallet or changing the passphrase, create a new backup
immediately. Encrypting a BLSCT wallet (the default) keeps its BLSCT keys, so
its mnemonic and earlier backups still recover its BLSCT coins. Only a
transparent HD seed, if the wallet has one, is replaced by a new one (as are a
descriptor wallet's descriptors). Coins received by the new seed cannot be
recovered from the previous backups.

The wallet's private key may be encrypted with the following command:

```
$ navio-cli -rpcwallet="wallet-01" encryptwallet "passphrase"
```

Once encrypted, the passphrase can be changed with the `walletpassphrasechange`
command.

```
$ navio-cli -rpcwallet="wallet-01" walletpassphrasechange "oldpassphrase" "newpassphrase"
```

The argument passed to `-rpcwallet` is the name of the wallet to be encrypted.

Only the wallet's private key is encrypted. All other wallet information, such
as transactions, is still visible.

The wallet's private key can also be encrypted in the `createwallet` command via
the `passphrase` argument:

```
$ navio-cli -named createwallet wallet_name="wallet-01" passphrase="passphrase"
```

Note that if the passphrase is lost, all the coins in the wallet will also be
lost forever.

### 1.3 Unlocking the Wallet

If the wallet is encrypted and the user tries any operation related to private
keys, such as sending coins, an error message will be displayed.

```
$ navio-cli -rpcwallet="wallet-01" sendtoblsctaddress "<blsct address>" 0.01
error code: -13
error message:
Error: Please enter the wallet passphrase with walletpassphrase first.
```

To unlock the wallet and allow it to run these operations, the
`walletpassphrase` RPC is required.

This command takes the passphrase and an argument called `timeout`, which
specifies the time in seconds that the wallet decryption key is stored in
memory. After this period expires, the user needs to execute this RPC again.

```
$ navio-cli -rpcwallet="wallet-01" walletpassphrase "passphrase" 120
```

### 1.4 Backing Up the Wallet

To backup the wallet, the `backupwallet` RPC must be used to ensure the file is
in a safe state when the copy is made.

In the RPC, the destination parameter must include the name of the file.
Otherwise, the command will return an error message like "Error: Wallet backup
failed!".

```
$ navio-cli -rpcwallet="wallet-01" backupwallet /home/node01/Backups/backup-01.dat
```

This backup file can be stored on one or multiple offline devices, which must be
reliable enough to work in an emergency and be malware free. Backup files can be
regularly tested to avoid problems in the future.

If the computer has malware, it can compromise the wallet when recovering the
backup file. One way to minimize this is to not connect the backup to an online
device.

If both the wallet and all backups are lost for any reason, the coins related to
this wallet will become permanently inaccessible.

### 1.5 Backup Frequency

The original Bitcoin Core wallet was a collection of unrelated private keys. If
a non-HD wallet had received funds to an address and then was restored from a
backup made before the address was generated, then any funds sent to that
address would have been lost because there was no deterministic mechanism to
derive the address again.

Bitcoin Core
[version 0.13](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.13.0.md)
introduced HD wallets with deterministic key derivation. With HD wallets, users
no longer lose funds when restoring old backups because all addresses are
derived from the HD wallet seed.

This means that a single backup is enough to recover the coins at any time. It
is still recommended to make regular backups (once a week) or after a
significant number of new transactions to maintain the metadata, such as labels.
Metadata cannot be retrieved from a blockchain rescan, so if the backup is too
old, the metadata will be lost forever.

### 1.6 Restoring the Wallet From a Backup

To restore a wallet, the `restorewallet` RPC must be used.

```
$ navio-cli restorewallet "restored-wallet" /home/node01/Backups/backup-01.dat
```

After that, `getwalletinfo` can be used to check if the wallet has been fully
restored.

```
$ navio-cli -rpcwallet="restored-wallet" getwalletinfo
```
