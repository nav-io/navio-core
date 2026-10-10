## Wallet RPC

- `consolidate` with `max_txs` greater than 1: if building or broadcasting a
  later transaction fails after at least one consolidation was already sent, the
  call now stops and returns the ids of the transactions it sent, instead of
  raising an error and losing them. The failure is written to the wallet log. A
  failure before anything is sent still raises an error as before.

  A short result therefore no longer always means the wallet ran out of outputs
  to merge. Calling `consolidate` again reports the error if it persists,
  because nothing has been sent yet on that call.
