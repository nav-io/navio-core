## Wallet

- BLSCT wallets now keep a privacy score for each of their coins, in bits:

      privacy_bits(coin) = log2(foreign inputs + 1) + min(privacy_bits(own inputs))

  where the foreign inputs are the inputs of the transaction that created the
  coin that are not coins of this wallet, and the own inputs are those that
  are. A coin received from someone else (including a coinbase or staking
  reward) scores 0: its sender knows it. The change of an ordinary send
  scores the lowest of the coins it spends. A coin served as a cover
  candidate that comes back out of another wallet's aggregate adds
  log2(foreign inputs + 1) to the score it had, so serving covers raises
  scores. Every coin of ours that a transaction spending one of our coins
  creates takes the same score, including a payment to us that another
  wallet's aggregate merged with our served cover.
- The score is computed when the transaction holding the coin is synced
  (mempool, block, rescan) or committed, from that transaction as it is then
  seen: a block transaction the staker merged our send into counts the
  foreign inputs it merged. It is stored with the coin, for both
  output-storage and full-transaction wallets; the storage format is
  backward compatible.
- `listblsctunspent` and `listunspent` (for BLSCT coins) report it as
  `privacy_bits`, a number with three decimals, or `null` when it is unknown.
  Coins synced before this version, and coins whose transaction spends such
  a coin, are unknown until `rescanblockchain` is run.
