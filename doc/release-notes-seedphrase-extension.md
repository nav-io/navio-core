## Updated RPCs

- The `createwallet` argument `mnemonic_passphrase` is renamed to
  `seedphrase_extension`. It is the optional BIP-39 passphrase combined with the
  mnemonic when deriving the keys of a BLSCT wallet, and is unrelated to the
  wallet encryption `passphrase`. Error messages now use the new name.
  `mnemonic_passphrase` is still accepted as a deprecated alias and will be
  removed in a future release. Passing both names is an error.

## Wallet tool

- The `navio-wallet` option `-mnemonicpassphrase` is renamed to
  `-seedphraseextension`. `-mnemonicpassphrase` is still accepted as a hidden,
  deprecated alias that prints a warning, and will be removed in a future
  release. Passing both options is an error.
- `-noseedphraseextension` and `-nomnemonicpassphrase` are now refused. Before,
  `-nomnemonicpassphrase` was accepted and derived the wallet with the extension
  `0`.

The rename does not change key derivation: a wallet restored with the same
mnemonic and extension derives the same keys under either name.
