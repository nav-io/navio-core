## Updated RPCs

- `removeprunedfunds` now fully forgets a send in a BLSCT wallet created with
  output storage (`storage_output`). Such a wallet also records a local send in
  its per-output records, and those were left behind: the send's change kept
  being counted in the balance and listed by `listblsctunspent`, and the coin it
  spent stayed spent, across restarts. The change is now removed and the spent
  coin is reported as unspent again, as a full-transaction wallet already did. A
  send the staker merged into a block transaction under another hash is the
  exception: that transaction spent the coin and created the change on chain, so
  both are kept.
