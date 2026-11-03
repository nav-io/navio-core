## Wallet

- When `createwallet` fails after it has created the wallet's database, for
  example because the BLSCT keys cannot be set up from the given seed, it now
  removes the wallet file and the wallet directory it created. Retrying with the
  same name used to fail with "Database already exists". A directory or wallet
  file that existed before the call, and any other file in the directory, is
  left in place. For a nested wallet name such as `a/b/c`, only the last
  directory (`c`) is removed; parent directories the call created stay behind,
  empty.
- While `createwallet` or `restorewallet` runs, including the removal of a
  failed attempt, `loadwallet`, `createwallet` and `restorewallet` of the same
  name are refused with "Wallet already loading.".
