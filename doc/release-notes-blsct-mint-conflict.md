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

Wallet
------

- A wallet transaction evicted this way is now marked conflicted with the
  block that caused the eviction (`confirmations` -1), so the coins it spent
  are available again without `abandontransaction`. If that block is
  disconnected, the transaction returns to unconfirmed.
