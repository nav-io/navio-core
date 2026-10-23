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

  Chains of aggregated sends make it more likely that a send leaves the mempool
  without confirming. Wallets with output storage now handle this as follows:
  - After a block conflict, for example when a cover provider's double-spend of
    its candidate input is mined, the wallet marks the aggregate and every send
    chained on it as conflicted, as Bitcoin Core does for non-BLSCT
    transactions: `confirmations` in `gettransaction` goes negative. When the
    double-spend is not a wallet transaction, such as a cover provider's,
    `walletconflicts` stays empty. Their inputs no longer count as spent, so the
    original coins are back in the balance and in `listblsctunspent` without
    `abandontransaction`. If the conflicting block is disconnected, they become
    unconfirmed transactions again that keep their inputs spent until they are
    abandoned. Previously the wallet kept them as unconfirmed and not abandoned,
    so the trusted balance and the coin set dropped, and sends failed with "Not
    enough funds available" until `abandontransaction <aggregate txid>` restored
    the original coins. The same now applies when another sender's aggregate
    using the same cover candidate is mined; the wallet used to count its own
    aggregate as confirmed then, although its own outputs never reached the
    chain.
  - After expiry, eviction or another removal that is not a block conflict, the
    transaction keeps its inputs spent until it is abandoned, but the wallet no
    longer treats it as in the mempool: it stops being trusted, and its change
    leaves `getbalances` and `listblsctunspent`. `abandontransaction <txid>` now
    accepts it and restores the coins it spent. Until then the wallet may
    rebroadcast it, at startup or periodically, and if the mempool accepts it
    again it counts as before. Previously the transaction stayed marked as in
    the mempool, `getbalances` kept counting it, and `abandontransaction` was
    refused until a restart resubmitted it.

  Only the wallet that broadcast the aggregate marks it as its own send. A
  wallet restored or reimported from the same seed (or any wallet that did not
  run the send) that learns of a still-unconfirmed aggregate from the mempool
  treats its change as untrusted pending, so a chained send from that wallet
  fails with "Not enough funds available" until the aggregate confirms. The
  wallet-local comment of the send is not recovered.

  For `consolidate` the trusted output is the merged coin, usually most of the
  wallet's small-coin balance, so an aggregate that is conflicted or leaves the
  mempool affects more of the balance at once; a later consolidation may also
  chain on that coin before the aggregate confirms.

  This covers `sendtoblsctaddress` and `consolidate` only. `aggregatesend` and
  `acceptquotewallet` still broadcast without recording the aggregate, so their
  change stays untrusted until it confirms (#510).
