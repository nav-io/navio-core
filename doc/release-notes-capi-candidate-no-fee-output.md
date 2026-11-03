## libblsct C API

Light wallets can now build fee-0 aggregation cover candidates, the
1-input/1-output self-spends that a wallet serving `AGG_ANN` requests sends
back, which another wallet merges into its aggregated send. Until now
`sign_unsigned_transaction` always appended an `OP_RETURN` fee output, and a
candidate with a fee output is rejected by `CandidatePool` (consensus allows
one fee output per transaction).

```c
void set_unsigned_transaction_emit_fee_output(void* vp_unsigned_transaction, bool emit_fee_output);
bool get_unsigned_transaction_emit_fee_output(const void* vp_unsigned_transaction);
```

- The default is `true`: signing works as before.
- With `false`, `sign_unsigned_transaction` emits neither the fee output nor
  its fee signature, like the node's own `TxFactoryBase::BuildTx` with
  `emitFeeOutput=false`. The inputs must balance the outputs exactly. Signing
  returns `BLSCT_FAILURE` if the fee is not 0.
- `get_unsigned_transaction_emit_fee_output` returns `true` for a NULL handle.

The serialized unsigned transaction (`serialize_unsigned_transaction`, and the
blobs `createblsctrawtransaction`/`signblsctrawtransaction` exchange) gains
format version 2, which appends the flag. It is written only when the fee
output is off; every other unsigned transaction keeps the version 1 layout,
so existing blobs and decoders are unaffected. Decoding now rejects unknown
format versions instead of misreading them.
