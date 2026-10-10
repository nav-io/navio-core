## Removed RPCs

- The node-level PSBT RPCs have been removed: `analyzepsbt`, `combinepsbt`,
  `converttopsbt`, `createpsbt`, `decodepsbt`, `descriptorprocesspsbt`,
  `finalizepsbt`, `joinpsbts` and `utxoupdatepsbt`. PSBTs only describe
  transparent transactions, which mainnet, testnet and blsctregtest do not
  accept; BLSCT transactions are built, inspected and signed with the wallet
  RPCs `createblsctrawtransaction`, `fundblsctrawtransaction`,
  `decodeblsctrawtransaction` and `signblsctrawtransaction` instead, so a node
  running with `-disablewallet` has none of them. Calling one of the removed
  RPCs now fails with "Method not found".
- The node can no longer inspect a PSBT before it is signed: `decodepsbt` and
  `analyzepsbt` have no replacement.
- The wallet PSBT RPCs have been removed as well; see the wallet PSBT RPC
  release notes.
