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

- On a wallet that stores full transactions (`storage_output=false`), an NFT
  input is no longer debited as NAV. An NFT output carries its value in the
  clear, and the wallet counted that value as NAV spent, so
  `simulaterawtransaction` overstated the NAV leaving the wallet when it spent
  an NFT, and `gettransaction` and `listtransactions` reported an NFT send's
  `amount` as that value instead of zero (the fee was unaffected).
