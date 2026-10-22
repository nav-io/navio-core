## Updated RPCs

- `migratewallet` now refuses a wallet it cannot migrate before touching it.
  Every wallet in this release is stored in SQLite already, which migration
  cannot convert, so the call fails with
  `Error: This wallet already uses SQLite` (or
  `Error: This wallet is already a descriptor wallet` for a loaded descriptor
  wallet). Before, it unloaded a loaded wallet, and for a legacy or BLSCT wallet
  also wrote a `<name>-<timestamp>.legacy.bak` backup, before failing, and did
  not load the wallet again. The wallet now stays loaded and unchanged, and no
  backup file is written.
