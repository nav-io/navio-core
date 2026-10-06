## Removed functionality

- External signer (hardware wallet) support has been removed. It worked by
  passing PSBTs for transparent outputs to an HWI-compatible tool, which BLSCT
  transactions never use. This removes the `-signer` option, the
  `enumeratesigners` and `walletdisplayaddress` RPCs, and the
  `ENABLE_EXTERNAL_SIGNER` build option. Passing `-signer` on the command line
  is now an invalid parameter error; a `signer=` line in the configuration file
  is ignored with a log message.

## Updated RPCs

- `createwallet` keeps its `external_signer` parameter so that the parameters
  after it keep their positions, but setting it to `true` is now an error.
  `false` or omitting it is accepted as before.
- `getwalletinfo` no longer returns the `external_signer` field.

## Wallet

- A wallet created with an external signer can no longer be loaded. `naviod` and
  `navio-wallet info` refuse it with the error "This wallet uses an external
  signer, which this build no longer supports". `navio-wallet dump` can still
  export its records, but `navio-wallet createfromdump` refuses such a dump with
  the same error instead of creating a wallet that cannot be loaded.
