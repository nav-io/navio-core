## Chainstate recovery

- After a crash or power loss in the middle of writing the chainstate to disk,
  the node replays the blocks between the last completed write and the tip on
  the next start. That replay now applies the token and NFT predicates (create,
  mint, NFT mint) of the replayed blocks, including those carried by a block's
  coinbase, and removes every staked commitment those blocks spent, even one
  whose coin the interrupted write had already erased. Previously tokens created
  or minted in the replayed blocks went missing, and such a spent staked
  commitment could stay in the staked-commitment set that PoS proofs are checked
  against, so the node could reject valid PoS blocks. A node in that state could
  also fail its startup block verification with "Corrupted block database
  detected". Replay now reads the undo data of the blocks it rolls forward as
  well as the blocks themselves.
- A node that crashed or was killed while writing the chainstate, in a stretch
  of blocks with token or NFT activity or with staking transactions, may still
  hold a wrong token set or staked-commitment set from before this release.
  Restart it once with `-reindex-chainstate` to rebuild both from the blocks; a
  pruned node can't use that and needs `-reindex`, which downloads the blocks
  again.

## Low-level changes

- Token entries are now written to the chainstate database only in the final
  batch of a write, together with the new best block, so they are never left
  half-written by an interrupted write. The debug options `-dbbatchsize` and
  `-dbcrashratio` no longer split or interrupt token writes; they still apply to
  coins.
