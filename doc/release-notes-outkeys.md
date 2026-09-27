P2P and network changes
-----------------------

- A new optional `-peeroutkeys` setting (default off) makes the node serve
  per-block BLSCT output keys to peers so light wallets can scan the chain
  without downloading range proofs. It is advertised with the new service bit
  `NODE_OUTKEYS` (bit 28, one of the bits reserved for experiments) and is
  incompatible with `-prune`, since replies are read from the block files.

  - `getoutkeys` (`uint32 start_height`, `uint256 stop_hash`) requests the range
    of active-chain blocks from `start_height` up to and including `stop_hash`,
    at most 1000 blocks. A request for an unknown or not yet servable stop
    block, a start above the stop block, or a larger range disconnects the
    peer, as does a request to a node that does not advertise `NODE_OUTKEYS`.
  - `outkeys` is sent once per block, in height order, and carries
    `uint256 block_hash`, then a vector with one entry per output carrying
    BLSCT keys, in block order (`uint256 output_hash`, 48-byte
    `blinding_key`, 48-byte `spending_key`, `uint16 view_tag`, and a
    `scriptPubKey` that is empty unless `spending_key` is the identity point),
    then a vector of the `uint256` output hashes spent by the block's inputs,
    in block order.

  A reply also stops early, before the first block whose `outkeys` would
  take the reply's total payload over 4,000,000 bytes. The first block is
  always sent, even if it alone is larger, so every request makes progress.
  A client that receives fewer blocks than it asked for continues with a new
  `getoutkeys` starting at the height after the last block it received.

  A wallet derives the nonce from `blinding_key` and its view key, discards
  outputs whose `view_tag` does not match, and resolves the subaddress from
  `spending_key` (or the keys in `scriptPubKey`). It then fetches the
  transactions of its own outputs, which carry the range proofs needed to
  recover amounts, for example with `getoutputdata`. The `spent` list tells it
  which of its outputs a block consumed.
