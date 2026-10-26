P2P and network changes
-----------------------

- A cover candidate received over p2pmsg is now checked before it enters the
  candidate pool, the way mempool acceptance would check it except for the
  minimum fee (a candidate is fee-0): its signature, balance and range proof,
  that its input is a confirmed unspent coin and, if a coinbase output, a
  mature one, and that no mempool transaction already spends that input.
  Candidates the pool would refuse anyway (wrong shape, input already pooled,
  pool full) are dropped before any of this work. Previously a forged
  candidate was pooled and only failed when an aggregate that picked it was
  broadcast.

Updated RPCs
------------

- `replycandidate` also returns `hex`, the serialized candidate that was sent.
