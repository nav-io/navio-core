## Updated RPCs

- `createwallet` now refuses `blank=true` together with `seed`, `mnemonic` or
  `mnemonic_passphrase` (`RPC_INVALID_PARAMETER`). A blank wallet is created
  without keys, so these used to be dropped silently, leaving a wallet that did
  not hold the seed it was given.
