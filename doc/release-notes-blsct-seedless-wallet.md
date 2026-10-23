## Wallet

- Loading a BLSCT wallet that has no seed, although it is neither blank nor
  watch-only, now fails with an error instead of aborting the node. Such a
  wallet is left behind when its creation does not complete; restore it from its
  mnemonic or seed, or from a backup.
- `navio-wallet create -blsct -seed=<seed>` now checks the seed first, as
  `createwallet` does: it must be hex, 64 characters for a master seed or 160
  for an audit key. Any other value used to create a wallet with no seed, or
  with a random seed whose mnemonic was never shown.
