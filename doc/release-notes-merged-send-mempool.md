## Wallet

- An output-storage wallet (`storage_output=true`) now treats its own send as in
  the mempool while a transaction that merges it (spends all of its inputs and
  creates all of its non-fee outputs) is in the mempool under its own hash. That
  is typically the block transaction a staker merged the send into, which the
  node puts back into its mempool when the block holding it is disconnected.
  Previously the send stayed unconfirmed outside the mempool: its change was
  untrusted in `getbalances` and missing from `listblsctunspent` while its
  inputs stayed spent, `abandontransaction` accepted it although the network
  could still mine it, and the wallet periodically rebroadcast it on its own,
  which the mempool rejects as a conflict with the merging transaction. When the
  merging transaction leaves the mempool without being mined (expiry, eviction,
  replacement or a conflict), the send leaves it too and can be abandoned. A
  send that was abandoned is no longer abandoned once a transaction merging it
  enters the mempool, as for any transaction that re-enters the mempool, and has
  to be abandoned again if that transaction leaves it unmined.
