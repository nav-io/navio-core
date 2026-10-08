Wallet
------

- Chained unconfirmed sends now work when `sendtoblsctaddress` aggregates a send
  with cover candidates (the default, `-aggregatesends`). Previously the wallet
  did not record its aggregated send until it found it in the mempool, and then
  treated the change as untrusted because the cover inputs belong to other
  wallets, so the next send failed with "Not enough funds available". The wallet
  now records the aggregate as its own send when it broadcasts it, together with
  the outputs of its own half, and those outputs (the change, or a payment to
  itself) count as trusted at 0 confirmations, like the change of a plain send.
  The wallet's own inputs are still checked.

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
  confirming keeps its inputs spent. This behaviour is not new, and it is
  tracked in #511, but chains of aggregated sends make it more likely:
  - After a block conflict, for example when a cover provider's double-spend of
    its candidate input is mined, the aggregate and every send chained on it
    leave the mempool. The wallet keeps them as unconfirmed transactions that
    are not abandoned, so their inputs still count as spent. The trusted balance
    and the coin set drop, and sends fail with "Not enough funds available"
    until `abandontransaction <aggregate txid>` restores the original coins.
  - After expiry or another removal that is not a block conflict, the
    transaction's outputs stop counting as coins, so `listblsctunspent` is
    empty, but the wallet transaction stays marked as in the mempool.
    `getbalances` keeps counting it, and `abandontransaction` is refused. A
    restart resubmits it, and the state is consistent again.

  Only the wallet that broadcast the aggregate marks it as its own send. A
  wallet restored or reimported from the same seed (or any wallet that did not
  run the send) that learns of a still-unconfirmed aggregate from the mempool
  treats its change as untrusted pending, so a chained send from that wallet
  fails with "Not enough funds available" until the aggregate confirms. The
  wallet-local comment of the send is not recovered.

  This covers `sendtoblsctaddress` only. `aggregatesend`, an aggregated
  `consolidate` and `acceptquotewallet` still broadcast without recording the
  aggregate, so their change stays untrusted until it confirms (#510).
