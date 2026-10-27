## Wallet

- An output-storage wallet (`storage_output=true`) now returns its own send to
  unconfirmed when the block that confirmed it is disconnected after a staker
  merged the send into one block transaction under another txid. Previously the
  send stayed confirmed in the disconnected block: its `confirmations` in
  `gettransaction` kept growing with each new block, its change counted as
  trusted in `getbalances` and `listblsctunspent` although it was no longer on
  the chain, `abandontransaction` refused it, and a later block that merged it
  again under yet another txid did not confirm it there. Restarting the wallet
  returned it to unconfirmed, but did not confirm it in such a later block. The
  send now behaves like any other wallet transaction of a disconnected block: it
  keeps its inputs spent until it confirms again, is conflicted, or is
  abandoned.
