## Wallet

- A cover candidate the wallet serves (through `-servecandidates` or
  `replycandidate`) now pays its coin back to the subaddress the coin was paid
  to, instead of to the change account. Once another wallet merges the
  candidate into a transaction that gets mined, the coin is still on its
  address: `getbalanceforaddress` and the address's label still show it.
  On chain nothing changes, since every BLSCT output has fresh one-time keys.
- The wallet recognises such an output as its own coin coming back: it
  carries the `candidate` memo and pays the same subaddress and amount as a
  coin of ours the same transaction spends. For output-storage wallets this
  is decided when the output is synced, and stored with it. `listtransactions` and related calls leave it
  out like change, so a served cover still adds no `send` or `receive` entry.
  A real payment to the same address in the same transaction is still listed
  as received.
