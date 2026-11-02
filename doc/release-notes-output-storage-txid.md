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

- `listunspent` on an output-storage wallet lists the change of the wallet's
  own sends once. It used to list it twice, once without an `address`, so the
  listed amounts summed to more than the balance. Every BLSCT coin is now listed
  with its address and recovered amount.
