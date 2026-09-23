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
key consensus verifies that output's ownership signature against.

What is signed is **not** the message itself but

```
digest = sha256("navio-blsct-output-auth/v1" || message)
```

with the 26-byte domain taken as raw ASCII and no NUL terminator. A verifier
recomputes that digest and does a plain BLS verify of `signature` against
`blindingkey`. The layout is normative and shared with navio-sdk; it is pinned
by `output_auth_digest_vector` in `src/test/blsct/wallet/blinding_key_tests.cpp`.

The domain prefix is not decoration. Consensus verifies a signature under an
output's `ephemeralKey` — the same point this RPC signs with — over that
output's 32-byte hash. Signing caller-chosen bytes would therefore turn the RPC
into a signing oracle for a consensus key: a caller could pass a 32-byte
"message" that is really an output hash and get back a consensus-valid output
signature. Hashing with a domain prefix means the signed value is always a
sha256 output, so producing a signature over a *chosen* output hash needs a
sha256 preimage.

The RPC refuses on a locked wallet, on an output the wallet did not create, and
on a transaction the wallet does not have (recovery needs the transaction's
inputs, so the output alone is not enough).

### Not retroactive

**Outputs created before this change are not recoverable, and cannot be made
recoverable.** Their blinding scalar was drawn at random and discarded the
moment the transaction was built; nothing about it is stored anywhere or
derivable from the seed. `signblsctoutput` fails cleanly on them. Recovery
applies only to outputs created by a wallet running this version or later.

### Generation

The derivation is otherwise a pure function of `(seed, anchor, ordinal)`, and a
wallet that rebuilds a transaction over the same inputs — abandon or evict and
resend, with coin selection being deterministic — would derive the **same** `k`
for a **different** amount. `k` seeds `nonce = vk * k`, from which the range
proof takes gamma and every blinding scalar, so two such published proofs would
reuse the prover's entire randomness and leak the committed values.

Each build therefore also commits to a **generation**: a per-anchor counter the
building wallet keeps and bumps on every build that reuses an anchor. It is
persisted (`blsctblindinggen`) and claimed once per build, before the outputs
are materialised, so a crash burns a generation rather than repeating one. The
counter is not a secret — it reveals nothing about any key — so unlike the
scalar it is stored in the clear.

Recovery cannot read that counter after a seed-only restore, so it searches:
generations `0..31` for each candidate anchor and ordinal. The common case is
still a single multiplication, since an output built by a wallet that never
rebuilt is generation 0, ordinal 0 on the canonical anchor.

**What this does and does not cover.** It covers one wallet rebuilding over one
input set, which is the case that occurs in normal operation. It does **not**
cover two wallets restored from the same seed: they share no counter, both
start at generation 0, and spending the same inputs from both derives the same
`k`. Do not run two wallets on one seed and spend from both.

If the counter cannot be persisted, the wallet falls back to a **random,
unrecoverable** blinding key for that output and logs it, rather than deriving
one it cannot prove is fresh. Losing recoverability is a lost fast path; reusing
a scalar would lose the amount.

### Anchor

The derivation is keyed on the transaction's *anchor* input: the lexicographically smallest
output hash among the inputs the sender itself contributed, comparing the 32 bytes in internal
order. It is canonical rather than positional because no position survives — `BuildTx` shuffles
`vin` before broadcast, and block aggregation then merges other senders' inputs into the same
transaction, so `vin[0]` may belong to a stranger.

Recovery tries the canonical anchor first (16 scalar multiplications) and then falls back to
scanning every input of the containing transaction. The fallback is deliberate: the search is
self-verifying against the output's ephemeral key, so a wrong anchor can only cost time, never
yield a false key — whereas relying on the canonical anchor alone would fail silently whenever a
wallet's notion of "my own inputs" differs between building and recovering, for instance after a
partial rescan.

### Notes

- The scalar is a secret of the sender. It is never logged, never stored, and a
  signature under it proves only who *created* the output, not who owns the
  funds now. `signblsctoutput` re-derives it from the seed on every call: an
  earlier revision of this feature kept a persisted copy as a fast path, but
  the wallet database writes such records in the clear even in an encrypted
  wallet, which would have put the signing authority for every output the
  wallet ever made into a stolen `wallet.dat`. Deriving instead costs at most
  16 scalar multiplications. Wallets written by that earlier revision have the
  plaintext records deleted on first open by this version.
- Outputs built with an explicitly supplied blinding key keep that key and stay
  unrecoverable. Aggregation cover candidates deliberately take this path: the
  scalars of one wallet's derived outputs share a derivation path, so making
  cover halves derived would let anyone holding the seed link them.
- The derivation is shared with navio-sdk and is fixed by a normative test
  vector (`src/test/blsct/wallet/blinding_key_tests.cpp`). It must not change.
