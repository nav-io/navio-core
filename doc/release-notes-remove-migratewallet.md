## Removed RPCs

- `migratewallet` is removed. It converted Berkeley DB legacy wallets to SQLite
  descriptor wallets, but Berkeley DB support is gone and every wallet is stored
  in SQLite already, so it could only refuse. Legacy wallets still load as
  before.
