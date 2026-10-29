P2P and network changes
-----------------------

- Mempool acceptance now bounds the `OP_BLSCHECKSIG` calls the input scripts
  of a BLSCT transaction may make, at 16 + 2 per input. Each call adds a pair
  to the aggregate signature check, which a peer could otherwise make the node
  evaluate for free before the signature is known to be bad. A transaction
  over the bound is rejected with the new reason
  `too-many-bls-signature-pairs`. Block validation is unchanged, so this is
  policy only: a coin locked to a script with more `OP_BLSCHECKSIG` calls than
  the bound is still valid in a block, but a spend of it is no longer accepted
  into the mempool or relayed.
