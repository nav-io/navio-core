## Updated RPCs

- `listtransactions`, `listsinceblock` and `listpendingtransactions` no longer
  report a `txid` for entries of an output-storage wallet
  (`storage_output=true`) that the wallet holds as a bare output, without the
  transaction that created it (`"output_storage": true`: payments received from
  others, staking rewards). Those entries used to carry the output id under
  `txid`, a copy of their `outid` that is not a transaction id. The field is now
  absent instead. `outid` still names the output; `gettxfromoutputhash` (or
  `getoutputinfo` with `-outindex`) finds the transaction holding it, and
  `gettransaction` still accepts the `outid` of such an entry. Entries for
  transactions the wallet built itself are unchanged and keep their `txid`.
  Rows in `listsinceblock`'s `removed` array are the exception: they come from
  reading the detached block, so they carry the `txid` of the transaction that
  held the output.

- `gettransaction` called with the `outid` of such an entry still returns that
  `outid` in its top-level `txid` field, because the field is required there.
  The value is an output id, not a transaction id; use `gettxfromoutputhash`
  to find the transaction.

- `listunspent` on an output-storage wallet lists the change of the wallet's
  own sends once. It used to list it twice, once without an `address`, so the
  listed amounts summed to more than the balance. Every BLSCT coin is now listed
  with its address and recovered amount.

- `listunspent` on an output-storage wallet no longer lists the outputs of a
  transaction that is neither confirmed nor in the mempool (for instance a
  send that expired from the mempool or was never relayed), even with
  `include_unsafe`. They were listed as unsafe 0-confirmation coins although
  no balance counts them; the full-transaction path never listed such coins.

## GUI

- The amount available to send no longer counts the change of the wallet's
  own unconfirmed or confirmed sends twice on an output-storage wallet.
