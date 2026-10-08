## Removed RPCs

- The node-level PSBT RPCs have been removed: `analyzepsbt`, `combinepsbt`,
  `converttopsbt`, `createpsbt`, `decodepsbt`, `descriptorprocesspsbt`,
  `finalizepsbt`, `joinpsbts` and `utxoupdatepsbt`. PSBTs only describe
  transparent transactions, which mainnet, testnet and blsctregtest do not
  accept; BLSCT transactions are built, inspected and signed with
  `createblsctrawtransaction`, `fundblsctrawtransaction`,
  `decodeblsctrawtransaction` and `signblsctrawtransaction` instead. Calling one
  of the removed RPCs now fails with "Method not found".
- The node can no longer inspect a PSBT before it is signed: `decodepsbt` and
  `analyzepsbt` have no replacement.
- The wallet PSBT RPCs (`walletprocesspsbt`, `walletcreatefundedpsbt`,
  `psbtbumpfee`) are still available. A PSBT that `walletprocesspsbt` completes
  is returned finalized in its `hex` field, ready for `sendrawtransaction`;
  without `combinepsbt`, multiple signers sign in series rather than in
  parallel.
