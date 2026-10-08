Updated RPCs
------------

- `gettxoutsetinfo` now hashes every coin in one canonical form: the coin's
  output id, its height and coinbase flag, and the output with BLSCT data in the
  form block-undo data stores it (range-proof body omitted). Previously a BLSCT
  output was hashed with its full range proof when it came from a block, but
  without it once it had been restored by a block disconnect, so the
  `hash_serialized_3` and `muhash` values of the same UTXO set could differ
  between nodes depending on their reorg history, and the `-coinstatsindex`
  muhash drifted away from the one computed from the UTXO set as soon as a BLSCT
  output was spent. On chains with BLSCT outputs both values change; values for
  coins without a range proof are unchanged.

Indexes
-------

- The coin statistics index (`-coinstatsindex`) now records the version of the
  coin hash it was built with. An existing index is wiped and rebuilt from the
  genesis block the first time the node starts after upgrading; this happens in
  the background; until it catches up, index-backed `gettxoutsetinfo` calls
  report that the index is still syncing (pass `use_index=false` to compute the
  values from the UTXO set instead). The rebuild needs the full block history,
  so a pruned node running with `-coinstatsindex` has to disable the index or
  `-reindex` after upgrading.
- Downgrading is not detected: an older release ignores the version record and
  keeps extending the index with the old coin hash, so its values silently go
  wrong. After downgrading, rebuild the index by deleting `indexes/coinstats` in
  the network's data directory (or with `-reindex`). Upgrading again does not
  repair it: the version record written by this release is still present, so the
  mixed index is not rebuilt either. Rebuild it the same way.
