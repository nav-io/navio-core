## Removed RPCs

- The wallet PSBT RPCs have been removed: `walletcreatefundedpsbt`,
  `walletprocesspsbt` and `psbtbumpfee`. Like the node PSBT RPCs removed before
  them, they only handle transparent transactions, which mainnet, testnet and
  blsctregtest do not accept. BLSCT transactions are built, signed and inspected
  with the wallet RPCs `createblsctrawtransaction`, `fundblsctrawtransaction`,
  `signblsctrawtransaction` and `decodeblsctrawtransaction` instead. Calling one
  of the removed RPCs now fails with "Method not found".
- With them the node has no RPC left that takes a PSBT, so a PSBT can no longer
  be signed, combined or finalized by the node.

## Updated RPCs

- The `psbt` option of `send` and `sendall` has been removed. Passing it is now
  an invalid parameter error, so a call that still asks for a PSBT fails instead
  of broadcasting a transaction. Use `add_to_wallet=false` to get the signed
  transaction in the `hex` field without broadcasting it. A transaction the
  wallet cannot fully sign is still returned as a PSBT in the `psbt` field, with
  `complete` set to `false`.
- `fundrawtransaction` no longer accepts a `psbt` key in its options, which it
  had ignored; passing it is now an error.
- `bumpfee` on a wallet with private keys disabled still fails, and its error no
  longer suggests `psbtbumpfee`. Such a wallet cannot bump a transaction's fee.
- A transaction with inputs from other wallets can no longer be fee-bumped.
  `psbtbumpfee` allowed it; `bumpfee` refuses with "Transaction contains inputs
  that don't belong to this wallet".

## Removed tools

- The signet miner (`contrib/signet/miner`) has been removed. It signed each
  block's signet challenge through `walletprocesspsbt`, and Navio's BLSCT chains
  are produced by staking, not by this tool. `contrib/signet/getcoins.py`
  remains.
