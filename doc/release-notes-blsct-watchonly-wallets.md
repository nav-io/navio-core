## Updated RPCs

- `createwallet` with `blsct=true` and `disable_private_keys=true` no longer
  generates a random seed: without a `seed` the wallet holds no keys. Wallets
  created this way before this release hold a full private seed, which
  `getblsctseed` and `dumpmnemonic` return.
- `createwallet` now refuses `disable_private_keys=true` together with a master
  `seed`, a `mnemonic` or a `mnemonic_passphrase`, which used to store the
  private keys in a wallet reporting `private_keys_enabled: false`. Pass an
  audit key (from `getblsctauditkey`) as `seed` to create a watch-only BLSCT
  wallet.
- `getblsctseed` and `dumpmnemonic` on a BLSCT wallet with private keys disabled
  now say so, instead of suggesting `setblsctseed`, which refuses such wallets.
