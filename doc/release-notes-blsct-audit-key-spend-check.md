## Wallet

- Creating a BLSCT wallet from an audit key (`createwallet` with a 160-character
  `seed`, or `navio-wallet create -blsct -seed=<audit key>`) now fails with
  "Invalid audit key" (`RPC_INVALID_PARAMETER` from `createwallet`) when the
  view-key half is zero or not below the group order, or the spend-key half is
  not a valid G1 point or is the identity. The key is checked before the wallet
  is created, so no wallet is left behind. Such a key used to be accepted,
  storing the identity as the spend key or a reduced view key, and the wallet
  then watched sub-addresses that are not the audited wallet's.
