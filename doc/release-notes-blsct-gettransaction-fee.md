## Updated RPCs

- `gettransaction` now reports the correct top-level `amount` and `fee` for
  BLSCT transactions the wallet sent. It used to compute the fee as inputs minus
  visible outputs, but confidential outputs carry no visible value, so the
  payment and the change were counted as fee: a send showed a large negative
  `fee` and a positive `amount`. For a transaction this wallet built, a send of
  X now reports `amount` -X and `fee` equal to its BLSCT fee output, matching
  its `details` entries and `listtransactions`; a send to the wallet's own
  address reports `amount` 0. A transaction in which this wallet's coins only
  served as aggregation cover, and all came back as change, reports `fee` 0. A
  merged block transaction that the wallet only learned of by rescanning reports
  the merged fee of every sender, as its `details` entries already did.
