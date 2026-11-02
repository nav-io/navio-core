Wallet
------

- A wallet with output storage now marks a received payment conflicted when the
  payment is evicted from the mempool because a block spends one of its inputs,
  or the input of a payment it descends from. Previously the payment stayed in
  `listtransactions` as an unconfirmed receive with 0 confirmations for good,
  also after a restart, although it can never confirm.

  Bitcoin Core drops a conflicted receive from `listtransactions` and reports
  negative `confirmations` for it in `gettransaction`. In a wallet with output
  storage the payment has no wallet transaction, so `gettransaction` does not
  know its txid, as before. The payment now leaves `listtransactions` and is
  listed by `listpendingtransactions` as a `receive` with negative
  `confirmations` (counted from the block that conflicts it), `trusted` false
  and its `outid` as `txid`. Balances and `listblsctunspent` already left such a
  payment out and still do. A send of this wallet that spends the payment's
  output is marked conflicted with the same block, so `gettransaction` reports
  negative `confirmations` for it instead of leaving it unconfirmed. If the
  conflicting block is disconnected, the payment and such sends become
  unconfirmed again.

  The payment stays unconfirmed, as before, when:
  - the block does not conflict it through inputs, for example when the mempool
    evicts it because the block adds the same staked commitment, or because it
    descends from a transaction of another wallet that the block conflicts;
  - it was not in this node's mempool when the conflicting block arrived;
  - the wallet loses the eviction before the block is reported to it: the wallet
    keeps evictions in memory until then, so a crash or `unloadwallet` in
    between drops them, and so does a block disconnected in between;
  - the conflicting block is disconnected and later connected again.

  `abandontransaction` still does not accept a received payment in a wallet with
  output storage.
