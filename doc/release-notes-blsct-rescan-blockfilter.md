Wallet
------

- A BLSCT wallet now always rescans by inspecting every block, even when the
  node runs with `-blockfilterindex=1`. Before, a BLSCT wallet without a legacy
  key manager, such as one created with `navio-wallet create`, took the fast
  rescan that uses block filters. BLSCT outputs are found by view key, not by a
  scriptPubKey a block filter can match, so that rescan skipped every block.
  Every rescan of such a wallet was affected: restoring it, loading it after
  blocks were mined while it was unloaded, and `rescanblockchain` all missed its
  transactions. If you ran such a wallet with `-blockfilterindex=1`, run
  `rescanblockchain` after upgrading to pick up anything that was missed. A
  BLSCT wallet created with the `createwallet` RPC before this release carries a
  legacy key manager and already used the slow rescan. Non-BLSCT descriptor
  wallets still use the fast rescan.
