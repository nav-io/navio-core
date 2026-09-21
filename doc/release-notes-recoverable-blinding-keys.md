## Recoverable output blinding keys

BLSCT outputs built by the wallet now take their blinding scalar from a
deterministic derivation over the wallet's HD seed instead of `Scalar::Rand()`.
The sender can therefore recompute the scalar of an output it created and sign
an arbitrary message with it, which is the only proof on chain that ties a
confidential output to whoever created it.

### New RPC

`signblsctoutput "txid" vout "message"` returns

```json
{ "signature": "<96-byte hex>", "blindingkey": "<48-byte public hex>" }
```

`blindingkey` is the output's ephemeral key, the point `k*G`, which is also the
key consensus verifies that output's ownership signature against. The message
is signed exactly as given — no length prefix and no hashing beyond what the
BLS scheme does — so it verifies with a plain BLS verify against `blindingkey`.

The RPC refuses on a locked wallet, on an output the wallet did not create, and
on a transaction the wallet does not have (recovery needs the transaction's
inputs, so the output alone is not enough).

### Not retroactive

**Outputs created before this change are not recoverable, and cannot be made
recoverable.** Their blinding scalar was drawn at random and discarded the
moment the transaction was built; nothing about it is stored anywhere or
derivable from the seed. `signblsctoutput` fails cleanly on them. Recovery
applies only to outputs created by a wallet running this version or later.

### Notes

- The scalar is a secret of the sender. It is never logged, and a signature
  under it proves only who *created* the output, not who owns the funds now.
- Outputs built with an explicitly supplied blinding key keep that key and stay
  unrecoverable. Aggregation cover candidates deliberately take this path: the
  scalars of one wallet's derived outputs share a derivation path, so making
  cover halves derived would let anyone holding the seed link them.
- The derivation is shared with navio-sdk and is fixed by a normative test
  vector (`src/test/blsct/wallet/blinding_key_tests.cpp`). It must not change.
