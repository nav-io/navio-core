## Updated RPCs

- `simulaterawtransaction` now reports the correct `balance_change` for BLSCT
  transactions. It read each output's visible value, which is zero for a
  confidential output, so a wallet receiving a BLSCT payment saw no change and
  the sender saw its whole input spent with no change returned. Outputs are now
  credited with the amount the wallet recovers from them, staked commitments
  count as the wallet's own, and only NAV outputs count toward the balance
  change (a transparent token output's value used to be added as NAV).
  Simulating a transaction with an out-of-range transparent output value now
  fails with an error instead of summing it.
