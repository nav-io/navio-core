New settings
------------

- A new optional `-outindex` index (default off) maps each output hash (the
  outpoint that spends it) to the block, transaction and output position that
  created it and, once a block spends it, to the block, transaction and input
  position of the spend. It follows reorganisations and is incompatible with
  pruning. It is built in the background for an existing chain and its state
  is reported by `getindexinfo` as `outindex`.

New RPCs
--------

- `getoutputinfo <outputhash>` (requires `-outindex`) returns the creating
  `txid`, `vout`, `blockhash`, `height` and `confirmations` of a confirmed
  output, whether a block in the active chain has spent it, and if so a
  `spentby` object with the spending `txid`, `vin`, `blockhash` and `height`.

Updated RPCs
------------

- `gettxfromoutputhash` answers confirmed outputs, including already spent
  ones, from `-outindex` when it is enabled and synced, instead of scanning the
  chain backwards. Without the index its behaviour is unchanged.
