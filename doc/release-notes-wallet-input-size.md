## Wallet

- Fee estimates for transparent wallet transactions no longer count a 4-byte
  output index per input, which navio outpoints do not carry. Each input was
  estimated 4 vbytes too large, so wallets overpaid by that much per input.
- `sendall` now pays enough fee when recipients are given without an amount. It
  used to estimate those outputs 8 vbytes too small each, so at the minimum
  relay feerate the transaction was rejected by the mempool while `sendall`
  still reported it complete.

## Updated RPCs

- `fundrawtransaction`'s `input_weights` option now works: any numeric `weight`
  used to fail with an internal error. The minimum accepted weight is now 149,
  the weight of an empty navio input.
