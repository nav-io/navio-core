## Updated RPCs

- `listtransactions`, `listsinceblock` and `gettransaction` no longer mark
  ordinary sends of an output-storage BLSCT wallet as `involvesWatchonly: true`.
  Any send spending a coinbase, stake or received coin was flagged, although the
  wallet held no watch-only scripts. A token input of such a wallet also no
  longer counts toward the NAV amount sent.
