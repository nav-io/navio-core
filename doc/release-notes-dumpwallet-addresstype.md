## Updated RPCs

- `dumpwallet` on a legacy (non-descriptor, non-BLSCT) wallet no longer aborts
  the node when it runs with `-addresstype=bech32m`. For keys without an address
  book entry the dump names an address of the `-addresstype` type, and neither
  `bech32m` nor `blsct` has one for a legacy key: `bech32m` hit an assertion and
  `blsct` wrote an empty `addr=` field. Those keys now show their `bech32`
  address instead, or their legacy address for an uncompressed key.
