Wallet
------

- Chained unconfirmed sends now work when `sendtoblsctaddress` or `consolidate`
  aggregates a send with cover candidates (the default, `-aggregatesends`).
  Previously the wallet did not record its aggregated send until it found it in
  the mempool, and then treated the change as untrusted because the cover inputs
  belong to other wallets, so the next send failed with "Not enough funds
  available". The wallet now records the aggregate as its own send when it
  broadcasts it, together with the outputs of its own half, and those outputs
  (the change, or a payment to itself) count as trusted at 0 confirmations, like
  the change of a plain send. The wallet's own inputs are still checked.

  Only the own half's outputs are trusted. Any other output of the aggregate
  that pays this wallet, such as a cover candidate addressed to it, is funded
  only by another wallet's input and stays untrusted pending, and out of the
  spendable coins, until the aggregate confirms.

  This accepts a risk: a cover provider can double-spend its coin, at the cost
  of one fee-0 candidate, and evict the aggregate from the mempool together with
  every unconfirmed send chained on its change, so those sends never confirm.
  The wallet handles the evicted aggregate like any other of its unconfirmed
  sends that leaves the mempool. A wallet that only received an aggregate, such
  as a cover provider's, still treats its outputs as untrusted until they
  confirm.

  In wallets with output storage, a transaction that leaves the mempool without
  confirming keeps its inputs spent until it is abandoned. Chains of aggregated
  sends make this more likely:
  - After a block conflict, for example when a cover provider's double-spend of
    its candidate input is mined, the aggregate and every send chained on it
    leave the mempool. The wallet keeps them as unconfirmed transactions that
    are not abandoned, so their inputs still count as spent. The trusted balance
    and the coin set drop, and sends fail with "Not enough funds available"
    until `abandontransaction <aggregate txid>` restores the original coins. The
    wallet does not yet detect this conflict itself (#511).
  - After expiry, eviction or another removal that is not a block conflict, the
    wallet transaction is no longer treated as in the mempool: it stops being
    trusted, and its change leaves `getbalances` and `listblsctunspent`.
    `abandontransaction <txid>` now accepts it and restores the coins it spent.
    Until then the wallet may rebroadcast it, at startup or periodically, and if
    the mempool accepts it again it counts as before. Previously the transaction
    stayed marked as in the mempool, `getbalances` kept counting it, and
    `abandontransaction` was refused until a restart resubmitted it.

  Only the wallet that broadcast the aggregate marks it as its own send. A
  wallet restored or reimported from the same seed (or any wallet that did not
  run the send) that learns of a still-unconfirmed aggregate from the mempool
  treats its change as untrusted pending, so a chained send from that wallet
  fails with "Not enough funds available" until the aggregate confirms. The
  wallet-local comment of the send is not recovered.

  For `consolidate` the trusted output is the merged coin, usually most of the
  wallet's small-coin balance, so the double-spend and #511 cases above can hold
  back more of the balance at once; a later consolidation may also chain on that
  coin before the aggregate confirms.

  This covers `sendtoblsctaddress` and `consolidate` only. `aggregatesend` and
  `acceptquotewallet` still broadcast without recording the aggregate, so their
  change stays untrusted until it confirms (#510).
