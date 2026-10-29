## Updated RPCs

- `gettransaction`, `listtransactions`, `listsinceblock` and
  `listpendingtransactions` now mark a BLSCT send whose `fee` may include fees
  that other wallets paid with `"fee_may_include_other_senders": true`, on the
  transaction and on its `send` entries. A staker merges every transaction of a
  block into one block transaction with a single fee output, and a wallet that
  learned of that transaction only by rescanning, without its own original
  sends, cannot tell its share of that fee from the other senders'. Such a send
  reports the whole fee, and an `amount` that leaves the other senders' fees
  out; their sum is still what the wallet spent. The field is absent for every
  other transaction, including a block transaction whose inputs are all the
  wallet's own, which pays only its fees.
