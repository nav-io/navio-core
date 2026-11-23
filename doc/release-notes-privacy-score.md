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
- BLSCT sends now prefer funding a payment from coins of similar scores, as
  the change scores the lowest coin spent: coins are grouped by whole bits
  (`floor(privacy_bits)`, unknown scores lowest), and if one group can fund
  the send alone the lowest such group is used, spending the least private
  coins first and keeping well-mixed ones. Otherwise coins are selected as
  before (largest first). The preference never makes a send fail. Staking,
  token creation, minting and consolidation select coins as before.
- `sendtoblsctaddress`, `sendtokentoblsctaddress`, `sendnfttoblsctaddress`
  and `aggregatesend` take a new `min_privacy` argument (bits, up to three
  decimals): only coins with `privacy_bits` at least that are spent, coins
  of unknown score are not, and a send they cannot fund fails with
  "Insufficient funds with privacy_bits >= X". For a token send the floor
  applies to the coins paying the fee too. Serving cover candidates
  (`replycandidate`, `-servecandidates`) is unaffected.
