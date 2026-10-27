## Wallet

- A BLSCT wallet that keeps full transactions (`storage_output=false`) now
  reports its own fee for a block transaction that replaced its sends. A staker
  merges every transaction of a block into one block transaction with a single
  fee output for all of them, and such a wallet replaces its merged sends with
  that transaction once it confirms. `gettransaction` and `listtransactions`
  used to report the whole block fee as the wallet's `fee`, and the amount sent
  to others less the other senders' fees. They now report the fees of the
  replaced sends and the amount those sends paid to others. The sum of `amount`
  and `fee`, and the balances, are unchanged. The block transaction's fee is
  still reported whole when the replaced sends do not account for everything the
  block transaction spends from the wallet (a coin of the wallet spent by a send
  it holds no record of), and for a wallet that only learned of the block
  transaction by rescanning. The wallet's own fee is stored with the transaction
  as an `ownfee` entry of its metadata, like the `ownhalf` entry of an
  aggregated send; an older version that loads the wallet shows it as an extra
  `ownfee` field in `gettransaction` and `listtransactions` and reports the
  whole block fee.
