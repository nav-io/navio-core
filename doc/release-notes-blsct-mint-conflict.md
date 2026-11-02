Mining and mempool
------------------

- Block templates no longer fail when the mempool holds token transactions
  that conflict with each other, such as two mints that are each valid on
  their own but together exceed the token's supply cap. Mempool acceptance
  checks each transaction's token predicates against the chain only, so both
  were accepted, and every template that selected both failed
  `TestBlockValidity` with `failed-to-execute-predicate`, stopping block
  production. Package selection now applies token predicates on top of the
  packages already chosen and skips a package that conflicts, so the block is
  filled with other transactions instead.

- After a block connects, mempool transactions whose token predicates no
  longer hold at the new tip (for example a mint of a token whose supply cap
  that block reached) are evicted, like transactions whose inputs the block
  spent. Only transactions touching a token the block changed are checked.
  After a reorg, mempool transactions whose token predicates no longer hold
  (for example a mint of a token whose creation the reorg undid) are evicted
  as well.

Wallet
------

- A wallet transaction evicted this way is now marked conflicted with the
  block that caused the eviction (`confirmations` -1), so the coins it spent
  are available again without `abandontransaction`. If that block is
  disconnected, the transaction returns to unconfirmed. When several blocks
  connect at once, the conflict is recorded against the block that touched
  the transaction's token.

- The wallet learns about such a conflict only from the mempool eviction and
  cannot rebuild it from chain state. A wallet that misses the eviction (it
  was not loaded at the time, the node stopped before the block was reported
  to it, or the transaction is found by a rescan), or a mint that confirmed on
  a chain later reorganized away and is rejected when resubmitted, leaves the
  transaction unconfirmed with its inputs spent, as before. Use
  `abandontransaction` to free them.
