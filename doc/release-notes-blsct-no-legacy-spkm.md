## Wallet

- A BLSCT wallet created with the `createwallet` RPC no longer gets a legacy key
  manager with a transparent HD seed beside its BLSCT keys, matching wallets
  made by `navio-wallet create`. Nothing on a BLSCT chain could use those
  transparent keys. Existing wallet files that have a legacy key manager still
  load and keep it. For a new BLSCT wallet:
  - `getwalletinfo` reports `keypoolsize` and `keypoolsize_hd_internal` as 0,
    since they count transparent keys only. `hdseedid` and `keypoololdest` still
    come from the BLSCT key manager.
  - A wallet created with a passphrase is still reported as not `blank` by
    `getwalletinfo`; its BLSCT seed now clears that flag.
  - `migratewallet` keeps refusing it with "This wallet already uses SQLite"
    rather than calling it a descriptor wallet.
  - `navio-wallet info` shows "HD (hd seed available): no" and "Keypool Size:
    0", as it already did for wallets made by `navio-wallet create`.
- On a BLSCT wallet, `keypoolrefill` with `blsct=true` (the default) now checks
  the BLSCT subaddress pool it refilled rather than the transparent key pool,
  which a new BLSCT wallet does not have. A size above 0 no longer fails with
  "Error refreshing keypool." With `blsct=false` a new BLSCT wallet has no
  transparent pool to refill, so a size above 0 still fails with that error.
- `keypoolrefill` on a view-only BLSCT wallet (one created from an audit key, or
  with `disable_private_keys`) fails with "Error: Private keys are disabled for
  this wallet", as it does on a legacy wallet without private keys.
