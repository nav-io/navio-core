## Wallet

- Loading a BLSCT wallet with private keys disabled that nevertheless holds a
  seed (such as one created with
  `createwallet blsct=true disable_private_keys=true` by an earlier release,
  which generated a random seed) now warns "Private keys detected in wallet ...
  with disabled private keys", as it already did for non-BLSCT wallets.
  Audit-key wallets hold no seed and load without the warning.
