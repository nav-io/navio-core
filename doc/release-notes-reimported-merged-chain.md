## Wallet

- A wallet restored or reimported from a seed after a staker merged a chain of
  its sends into one block transaction now reports the correct amount for that
  transaction. Each send in the chain spends the change of the one before, and
  the block transaction keeps those intermediate change outputs together with
  the inputs that spend them. The wallet already left those inputs out of the
  amount it spent, but it still subtracted the intermediate change as returned
  to itself, so `listtransactions` and the `details` of `gettransaction` showed
  one `send` with a large positive amount. The intermediate change is now left
  out on both sides, and the row shows the amount paid to others with the merged
  transaction's fee. Balances and `listblsctunspent` were already correct and
  are unchanged (#512).

  The restored wallet still shows the whole chain as one `send` row under the
  block transaction's txid, not one row per original send: the block transaction
  does not record where one send ends and the next begins. An output-storage
  wallet (`storage_output=true`) that made the sends, or saw them in the mempool
  before they were mined, keeps one row per send. Other BLSCT wallets replace
  the merged sends with the block transaction when it confirms, so they also
  show the single row, now with the correct amount. A wallet whose only
  involvement in the block transaction is an output it also spent there now
  lists no `listtransactions` row for it (`gettransaction` still returns it,
  with amount 0 and no details), since that output and the input spending it are
  both left out.
