## Wallet

- `gettransaction` and `listtransactions` now report a swap taken with
  `acceptquotewallet` with a `fee` of 0 and an `amount` of the full sell cost,
  on the transaction and on its `send` entry. The maker's half funds the whole
  fee of the swap, but the taker's wallet used to report that fee as its own,
  and an `amount` short of the sell cost by the same figure. The sum of `amount`
  and `fee`, and the balances, are unchanged. The taker's fee is stored with the
  swap as an `ownfee` entry of its metadata, like the own fee of a block
  transaction that replaced the wallet's sends, so it survives a reload, and a
  block transaction a staker merges the swap into adds none of the swap's fee to
  the wallet's own. Swaps recorded before the upgrade keep the old figures.
