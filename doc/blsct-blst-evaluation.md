# BLSCT arithmetic backend: herumi/mcl vs supranational/blst

Evaluation of migrating the BLS12-381 arithmetic under BLSCT (range proofs,
PoS set-membership proofs, BLS signatures, wallet recovery) from
[herumi/mcl](https://github.com/herumi/mcl) + [herumi/bls](https://github.com/herumi/bls)
to [supranational/blst](https://github.com/supranational/blst).

> **Status.** This document is the evaluation that preceded the migration.
> The numbers were measured with both libraries side by side on the
> `eval/blst-arith-backend` branch (PR #386), whose `-DWITH_BLST=ON` build
> carried a two-backend benchmark (`BLSCTCmp_*`) and equivalence test suite.
> mcl has since been removed from the tree: blst is the only backend
> (`src/blst`, `cmake/blst.cmake`), the wrappers live in
> `src/blsct/arith/blst/`, and the historical "release config" numbers below
> are what the mcl-based binaries did. The "Full chain sync" section carries
> the measured (not projected) blst figure from the migrated node.

## TL;DR

* **Compatibility: exact.** Every value BLSCT puts on the wire or hashes into
  a transcript — Fr/G1/G2 encodings, SSWU map-to-G1, hash-to-G1/G2, public
  keys, signatures, range proofs, set-membership proofs, recovered amounts —
  is bit-identical between mcl and blst. Checked on every benchmark fixture
  and in a new unit-test suite; proofs cross-verify in both directions.
* **Speed, single-threaded:** range-proof verify **2.3–2.6×**, prove 1.5×,
  amount recovery 3.4×, balance scan 1.5×, PoS set-membership verify
  **2.1–4.2×** (ring 16: 2.5×), aggregate signature verify **2.2–2.5×**,
  MSM 2.3× at proof size up to 4.7× at 8192 points, hash-to-curve 2–2.8×,
  subgroup-checked decode 3.8×.
* **Speed, multi-threaded (12 cores):** blst's tiled MSM scales ~5–6× and
  stays **2.4–3.5×** ahead of mcl+OpenMP on MSM, **2.1–2.4×** on range-proof
  verify, 2.1–4.9× on set-membership verify, 2.5–4.1× on aggregate verify.
* **Full mainnet sync (39.6k blocks, reindex-chainstate):** measured mcl
  571 s (release config) / 447 s (OpenMP build); projected blst ≈ 290–330 s
  (**1.7–2×** vs release, 1.5× vs OpenMP) from the measured per-operation
  ratios applied to the measured per-block breakdown.
* **Not just speed:** blst drops OpenMP (and the libomp/`std::async`
  hazards that forced `pos_async_verifier.h`), the vendored bls patch, the
  in-source Makefile build, and ~200 µs/point of redundant subgroup work mcl
  does on every decode.
* **Cost:** a mechanical port of ~90 files that still name `MclG1Point`
  (mostly type aliases), the signature layer, the decode-scope helpers, and a
  differential fuzzer for malformed-encoding acceptance before flipping the
  default. Recommendation: migrate, staged (see the end of this document).

## What was evaluated

| Layer | mcl (production) | blst (this PR) |
|---|---|---|
| Fr | `mclBnFr_*` | `blst_fr_*` (Montgomery) + `blst_scalar` for canonical bytes |
| G1 | `mclBnG1_*` (Jacobian) | `blst_p1_*` (Jacobian), `blst_p1_affine` for MSM / (de)serialization |
| Serialization | mcl "ETH serialization" (ZCash compressed, 48 B / 96 B) | `blst_p1_compress` / `blst_p1_uncompress`, `blst_p2_*` — **identical bytes** |
| Subgroup check | `mclBnG1_isValidOrder` (scalar-mul by r) | `blst_p1_in_g1` (endomorphism-based, much cheaper) |
| map-to-G1 (generators, `MapToPoint`) | `mclBnFp_mapToG1` (SSWU + iso-11 + h_eff, RFC 9380 mode) | `blst_map_to_g1(u, NULL)` — **identical points** |
| hash-to-G1 / G2 | `mclBnG1/G2_hashAndMapTo` with `BLS_SIG_BLS12381G{1,2}_XMD:SHA-256_SSWU_RO_POP_` | `blst_hash_to_g{1,2}` with the same DST — **identical points** |
| MSM (`LazyPoints::Sum`, ~90% of verify time) | `mclBnG1_mulVecMT` (Pippenger; OpenMP if `MCL_USE_OMP`) | `blst_p1s_mult_pippenger`; MT via `blst_p1s_tile_pippenger` window tiling over `std::thread` (`BlstUtil::MSM`) |
| Signatures (min-pk, aug. messages) | `blsSign` / `blsVerify` / navio-patched `blsAggregateVerifyNoCheck` (std::async inside) | `blst_sign_pk_in_g1`, `blst_core_verify_pk_in_g1`, `blst_pairing_*` contexts (merged per thread) — **identical signature bytes** |
| Bignum string I/O (`GetString`/`SetString`, debug only) | `mclBnFr_getStr` etc. | none in blst; ~80 lines of helper (`blst_strconv.h`) |
| Init | `blsInit(MCL_BLS12_381)` + `mclBn_setETHserialization(1)`, must run before use | none (no global state) |
| Threads | OpenMP (mcl) + std::async (bls patch) | caller-managed only |

The full navio operations were run through the **same templated code**
(`RangeProofLogic<T>`, `SetMemProofProver<T>`, `Elements<T>`, ...) with
`T = Mcl` and `T = Blst`; the only generic-code change needed was
`WeightedInnerProdArg::Run<Mcl>` → `Run<T>` inside `RangeProofLogic<T>::Prove`
(the one place the template was accidentally pinned to mcl). Proofs produced
by either backend are transcoded through the wire format and verified by the
other, and amount recovery / set-membership verdicts are compared.

### Compatibility findings

* **Wire compatibility is exact.** Fr / G1 / G2 encodings, the G1 generator,
  `MapToPoint` (little- and big-endian, 32- and 64-byte inputs, i.e. every
  generator derivation in the codebase), `HashAndMap` (G1), hash-to-G2,
  public keys, signatures and aggregate signatures are bit-identical across
  the two libraries. Range proofs and set-membership proofs cross-verify in
  both directions and `RecoverAmounts` returns the same amounts / gammas /
  messages. This is checked on every bench fixture construction and in
  `blst_equivalence_tests`. A backend swap therefore has no consensus
  surface on the *values* side.
* **`MclG1Point::SetVchUnchecked` is not unchecked.** `blsInit()`
  (`src/bls/src/bls_c_impl.hpp:152`) calls `verifyOrderG1(true)` /
  `verifyOrderG2(true)`, so `mclBnG1_deserialize` already performs the full
  order check (a 255-bit scalar multiplication) on every point; the
  "deferred batch subgroup check" path then repeats the work as a random
  linear combination. With blst, `uncompress` checks the curve equation only
  and `blst_p1_in_g1` is a cheap endomorphism test, so both the per-point and
  the batched check become almost free (see `G1DeserializeUnchecked` /
  `G1DeserializeSubgroup` / `G1SubgroupCheck` below). Independently of any
  migration, the mcl deferral scope can be simplified.
* mcl's `setLittleEndianMod` / `setBigEndianMod` for Fp reject inputs longer
  than 64 bytes (the wrapper advertises 96). The blst backend reduces any
  length exactly; only ≤ 64 bytes was cross-checked.
* **`WITH_MCL_OPENMP` is fragile in the cmake build.** mcl/bls are built
  *in-source* by their GNU Makefiles (`BUILD_IN_SOURCE TRUE` in
  `cmake/bls.cmake`), so `src/bls/mcl/lib/libmcl.a` is shared by every build
  directory and `make` does not track flag changes: an OpenMP-enabled build
  directory silently reuses non-OpenMP objects left by an earlier build (and
  vice versa) unless `make -C src/bls/mcl clean` is run by hand. The first
  OpenMP run of this evaluation linked a non-OpenMP `libmcl.a` for exactly
  that reason (caught with `nm | grep omp_get_num_procs`). blst is a single
  `server.c` + `assembly.S` and can be compiled per build directory.
* Semantics that had to be reproduced by hand in the blst wrapper (all
  covered by the equivalence tests): negative `int64` construction, `>>` /
  `<<` / bitwise ops over the canonical representative, `operator/` with a
  zero divisor mapping to zero, mcl's `"1 x y"` point string format, radix
  2/10/16 string I/O, `IsValid()` meaning "on curve" for G1.
* Not reproduced (evaluation scope): the thread-local
  `SubgroupCheckDeferralScope` / `SubgroupCheckSkipScope` /
  `LegacyPointDecodeScope` machinery on `MclG1Point`, the `FixedBaseCache`
  fast path (mcl-only by construction, disabled by default) and the
  wallet/PoS glue that names `MclG1Point` directly (`KeyMan`, `ProofOfStake`,
  `Signature`, `PublicKey(s)`, EIP-2333 keygen, `pos/proof.h`,
  `blockstorage.cpp`, `txdb.cpp`). These are mechanical to port.

### Threading

mcl parallelises inside the library: `mulVecMT` splits the point set across
OpenMP threads (only when built with `MCL_USE_OMP=1`, which the cmake build
exposes as `WITH_MCL_OPENMP` and which is **off** for release binaries), and
navio's patched `blsAggregateVerifyNoCheck` always fans hash-to-G2 + Miller
loops out over `std::thread::hardware_concurrency()` `std::async` tasks.
`RangeProofLogic::VerifyProofs` additionally runs one `std::async` worker per
proof unless `HAVE_OPENMP` is defined — which the cmake build never defines,
so an OpenMP build nests both levels. The libomp/`std::async` interaction is
also what forced the persistent-worker design in `pos_async_verifier.h`.

blst has no threads of its own. The prototype threads at the two places that
matter and nowhere else: `BlstUtil::MSM` tiles the 255-bit scalar range into
Pippenger windows (`blst_p1s_tile_pippenger`) and folds them back with
window-sized doublings (the scheme blst's own Rust bindings use), and the
aggregate-verify bench keeps one `blst_pairing` context per thread and
`blst_pairing_merge`s them. Both are bit-identical for any thread count.
Because threading is explicit, a migration can also choose the outer
per-proof / per-block parallelism that navio already has (`VerifyProofs`
workers, `-par`, the PoS async verifier) without any library runtime.

## Results

### x86_64 cross-check (AMD EPYC 9354) and an architecture note

The original numbers below are Apple M2 Max (arm64). Re-running the same
`BLSCTCmp_*` suite on an AMD EPYC 9354 (x86_64, ADX confirmed in `libblst.a`
via `nm | grep mulx_384`; mcl built `WITH_GMP=OFF`) shows a very different
single-threaded picture, while the multi-threaded/large-MSM story is
unchanged:

| operation | M2 (blst/mcl) | EPYC (blst/mcl) |
|---|---:|---:|
| MSM 2048 (MT) | ~3.4× | 21× |
| MSM 8192 (MT) | — | 29× |
| SetMemVerify 1024 (MT) | — | 8.3× |
| Range-proof verify ×32 (ST) | — | 1.35× |
| Sign | — | 1.17× |
| **RecoverAmounts ×16 (ST)** | **~3.4×** | **0.62×** |
| Range-proof prove (ST) | ~1.5× | 0.92× |
| SetMemProve ring 4 (ST) | — | 0.80× |
| MSM 16 (small, ST) | — | 0.72× |

**Architecture note.** mcl carries an xbyak-JIT hand-tuned x86-64 assembly
path for its `Fr` field arithmetic. On x86_64 that path is strong enough to
beat blst's `Fr` single-threaded for scalar-heavy operations (amount
recovery, range-proof prove, small-ring set-membership prove) *even with
`WITH_GMP=OFF`* — hence the sign flip vs the arm64 numbers, where mcl has no
comparable JIT path and blst wins those same ops. The point/MSM/pairing side
still favours blst on both architectures (and blst's threaded MSM dominates
at scale). So on x86_64 the migration's wins concentrate in the MSM- and
pairing-bound paths, and the scalar-bound paths need help to not regress:
this is exactly why the fixed-base generator precompute (removes the fixed
Gi/Hi/hs points from the per-call MSM) and the threaded amount recovery
matter more on x86_64 than the arm64 headline suggested. Measured on this
EPYC: full mainnet `-reindex-chainstate` is 258s baseline vs 227s with the
fixed-base precompute (~12%).


Host: Apple M2 Max (12 cores), macOS, clang, `-O2`/Release; mcl built by its
GNU Makefile (`MCL_USE_LLVM=0`, no GMP, arm64), blst v0.3.17 with its arm64
assembly. `bench_navio -filter='BLSCTCmp_.*' -min-time=500`. mcl "MT"
columns come from a second build with `-DWITH_MCL_OPENMP=ON`; the blst
columns are the same code in both builds.

How to read the tables:

* `*_ST` / `*_MT`: single- vs multi-threaded variant of the same operation.
  For mcl, MSM threading comes from OpenMP (`mulVecMT`), so the "no OpenMP
  build" MT column equals ST for MSM-bound ops; aggregate verify uses the
  std::async patch in either build. For `RPVerify*` / `SetMemVerify*` /
  `BalanceScan*` the mcl numbers have no ST/MT suffix — its threading is
  whatever the build gives (`RPVerify` with n > 1 always uses navio's
  per-proof std::async workers; the OpenMP build additionally threads each
  MSM). blst "MT" = `BlstUtil::MSM` window tiling (+ per-proof workers for
  n > 1, i.e. nested).
* `RPVerify<n>` is per proof in a batch of n; `AggVerify<n>` per (pk, msg)
  pair; `BalanceScan4096` per scanned output (4096 outputs, 16 of them ours →
  view-tag for every output, nonce + `RecoverAmounts` for the 16);
  `Msm<n>` per n-point MSM; `SetMemVerify<n>` per proof over a ring of n.
* `Msm150` ≈ the MSM of one single-value 64-bit range proof, `Msm2048` ≈ a
  16-value aggregated proof. `SetMemVerify16` is today's typical mainnet PoS
  ring (37k of 39.6k blocks; 8 and 2/4 are the rest).

Highlights:

* **Field/point primitives**: blst is 1.2–1.5× faster on the basic G1/Fr
  ops (constant-time assembly vs mcl's generic C++ with `MCL_USE_LLVM=0`),
  2× on map/hash-to-G1, 2.8× on hash-to-G2, 7× on Fr inversion.
* **Decoding**: 4× on a subgroup-checked decode (blst's `in_g1` is an
  endomorphism check, mcl multiplies by r) and 10× on the "unchecked" one
  (which mcl secretly still order-checks, see above). Serialization 6×
  (blst's cheaper inversion when normalising).
* **MSM** (the verifier hot loop): 2.3× at proof size, 3–4.7× at 512–8192
  points single-threaded. Threaded, mcl/OpenMP gets ~4.8–7.9× from 12
  cores; blst's tiling gets ~5–6× and stays 2.4–3.5× ahead of mcl+OpenMP.
  At n = 16 both are equal (the MSM is dominated by fixed costs).
* **Signatures**: sign 2.2×, single verify 1.9×, aggregate verify 2.2–2.5×
  single-threaded and 2.5–4.1× against navio's std::async-patched
  `blsAggregateVerifyNoCheck` (blst's merged pairing contexts scale ~7× on 12
  threads vs ~6× for the patch).
* **Range proofs**: prove 1.46×; verify 2.3–2.6× per proof at every batch
  size single-threaded (the whole verifier moves, not just the MSM). With
  threads, mcl+OpenMP brings a lone proof from 6.7 → 1.7 ms, blst from
  2.9 → 0.71 ms; for batches ≥ 16 the per-proof workers already saturate the
  cores and inner MSM threading adds nothing in either library (blst ends
  ~2.1–2.2× ahead of mcl+OpenMP).
* **Amount recovery / balance scan**: `RecoverAmounts` 3.4×; the full
  view-tag scan is 1.5× (it is one scalar mult per output, 1.26× on its own,
  plus hashing) and 1.7× threaded.
* **PoS set-membership**: verify 2.1–4.2× single-threaded (ring 16: 4.5 →
  1.8 ms), 2.1–4.9× against mcl+OpenMP; prove 1.25–1.66×.
* The `FrSerialize` 0.87× is the one place blst is slower: its
  `blst_scalar_from_be_bytes` does a full Montgomery reduction on the way
  in and out; irrelevant at 150 ns.

#### Single-threaded primitives / operations (ns per op)

| operation | mcl | blst | mcl/blst |
|---|---:|---:|---:|
| `FrAdd` | 7 ns | 3 ns | 2.28× |
| `FrInv` | 10.1 µs | 1.4 µs | 7.29× |
| `FrMul` | 17 ns | 14 ns | 1.20× |
| `FrSerialize` | 131 ns | 150 ns | 0.87× |
| `FrSqr` | 18 ns | 14 ns | 1.30× |
| `G1Add` | 739 ns | 565 ns | 1.31× |
| `G1DeserializeSubgroup` | 195.5 µs | 50.9 µs | 3.84× |
| `G1DeserializeUnchecked` | 125.2 µs | 12.5 µs | 10.05× |
| `G1Double` | 388 ns | 259 ns | 1.50× |
| `G1HashToCurve` | 103.0 µs | 50.7 µs | 2.03× |
| `G1MapToPoint` | 74.0 µs | 36.6 µs | 2.02× |
| `G1MulBase` | 91.1 µs | 73.0 µs | 1.25× |
| `G1Mul` | 92.5 µs | 73.5 µs | 1.26× |
| `G1Serialize` | 17.0 µs | 2.8 µs | 5.99× |
| `G1SubgroupCheck` | 72.9 µs | 38.1 µs | 1.91× |
| `G2HashToCurve` | 423.6 µs | 151.7 µs | 2.79× |
| `RPProve` | 46.37 ms | 31.71 ms | 1.46× |
| `RecoverAmounts16` | 954.4 µs | 282.4 µs | 3.38× |
| `SetMemProve1024` | 779.65 ms | 469.69 ms | 1.66× |
| `SetMemProve16` | 13.60 ms | 10.43 ms | 1.30× |
| `SetMemProve4` | 3.97 ms | 3.19 ms | 1.25× |
| `SetMemProve64` | 50.86 ms | 35.04 ms | 1.45× |
| `Sign` | 652.5 µs | 301.4 µs | 2.17× |
| `Verify1` | 1.69 ms | 899.2 µs | 1.88× |

#### Threaded operations: single-threaded

| operation | mcl ST | blst ST | mcl/blst |
|---|---:|---:|---:|
| `AggVerify1024` | 732.5 µs | 296.7 µs | 2.47× |
| `AggVerify16` | 802.8 µs | 327.4 µs | 2.45× |
| `AggVerify256` | 741.8 µs | 296.0 µs | 2.51× |
| `AggVerify2` | 1.22 ms | 558.0 µs | 2.19× |
| `BalanceScan4096` | 116.1 µs | 77.6 µs | 1.50× |
| `Msm150` | 6.50 ms | 2.79 ms | 2.33× |
| `Msm16` | 692.2 µs | 639.5 µs | 1.08× |
| `Msm2048` | 86.35 ms | 22.26 ms | 3.88× |
| `Msm512` | 22.18 ms | 7.24 ms | 3.06× |
| `Msm64` | 2.75 ms | 1.49 ms | 1.84× |
| `Msm8192` | 353.09 ms | 74.75 ms | 4.72× |
| `RPVerify16` | 1.15 ms | 440.6 µs | 2.61× |
| `RPVerify1` | 6.67 ms | 2.89 ms | 2.31× |
| `RPVerify32` | 971.0 µs | 398.4 µs | 2.44× |
| `RPVerify4` | 1.88 ms | 782.0 µs | 2.41× |
| `SetMemVerify1024` | 125.17 ms | 29.96 ms | 4.18× |
| `SetMemVerify16` | 4.48 ms | 1.79 ms | 2.50× |
| `SetMemVerify4` | 2.51 ms | 1.21 ms | 2.07× |
| `SetMemVerify64` | 10.81 ms | 3.64 ms | 2.97× |

#### Threaded operations: multi-threaded (12 threads)

| operation | mcl MT (no OpenMP build) | mcl MT (OpenMP build) | blst MT | mcl(OMP)/blst | blst MT speedup vs blst ST |
|---|---:|---:|---:|---:|---:|
| `AggVerify1024` | 115.9 µs | 114.3 µs | 42.7 µs | 2.68× | 6.95× |
| `AggVerify16` | 345.0 µs | 351.7 µs | 85.4 µs | 4.12× | 3.84× |
| `AggVerify256` | 122.7 µs | 114.1 µs | 45.1 µs | 2.53× | 6.57× |
| `AggVerify2` | 1.40 ms | 1.40 ms | 436.5 µs | 3.21× | 1.28× |
| `BalanceScan4096` | 17.3 µs | 17.2 µs | 10.0 µs | 1.72× | 7.75× |
| `Msm150` | 6.54 ms | 1.36 ms | 564.0 µs | 2.41× | 4.95× |
| `Msm16` | 695.3 µs | 685.4 µs | 640.1 µs | 1.07× | 1.00× |
| `Msm2048` | 85.90 ms | 12.81 ms | 3.78 ms | 3.39× | 5.89× |
| `Msm512` | 22.17 ms | 3.40 ms | 1.20 ms | 2.84× | 6.06× |
| `Msm64` | 2.75 ms | 1.40 ms | 417.6 µs | 3.34× | 3.57× |
| `Msm8192` | 352.75 ms | 44.83 ms | 12.66 ms | 3.54× | 5.90× |
| `RPVerify16` | 1.15 ms | 978.5 µs | 445.7 µs | 2.20× | 0.99× |
| `RPVerify1` | 6.67 ms | 1.73 ms | 712.9 µs | 2.43× | 4.06× |
| `RPVerify32` | 971.0 µs | 934.6 µs | 445.7 µs | 2.10× | 0.89× |
| `RPVerify4` | 1.88 ms | 1.21 ms | 503.2 µs | 2.41× | 1.55× |
| `SetMemVerify1024` | 125.17 ms | 49.97 ms | 10.30 ms | 4.85× | 2.91× |
| `SetMemVerify16` | 4.48 ms | 3.33 ms | 845.6 µs | 3.93× | 2.12× |
| `SetMemVerify4` | 2.51 ms | 2.51 ms | 1.20 ms | 2.09× | 1.01× |
| `SetMemVerify64` | 10.81 ms | 5.58 ms | 1.35 ms | 4.15× | 2.70× |


### Full chain sync (mainnet, `-reindex-chainstate`)

Mainnet at height 39,645 (2026-08-29), synced from the network once, then
re-validated from local block files with
`contrib/devtools/blsct-sync-bench.sh` (no network, `-reindex-chainstate`,
default `-par`, `-debug=bench`). The chain is ~97% "2 range proofs + 2
signature pairs + PoS ring of 16" blocks, so per-block cost is essentially
`RPVerify` of a 2-proof batch + `AggVerify2` + `SetMemVerify16`.

Measured, mcl (this tree, Release, no OpenMP — the configuration release
binaries ship with):

```
reindex-chainstate to height 39645: 571.3s wall (14.41 ms/block)
  Connect block                                     568.5s    14.34 ms/blk
  Connect total                                     296.1s     7.47 ms/blk
  Verify block proofs/scripts                       278.9s     7.03 ms/blk
  BLSCT aggregate signatures                        120.9s     3.05 ms/blk
  BLSCT reward/stake tx collect                       7.5s     0.19 ms/blk
  Write undo data                                     0.2s     0.01 ms/blk
  BLSCT block rangeproof batch (all sizes)          265.0s     6.69 ms/blk
  PoS setmem (async worker CPU, summed)              98.2s     2.48 ms/blk
```

Measured, mcl + OpenMP (`-DWITH_MCL_OPENMP=ON`, fresh mcl objects):

```
reindex-chainstate to height 39645: 447.1s wall (11.28 ms/block)
  Connect block                                     443.7s    11.19 ms/blk
  Connect total                                     172.2s     4.34 ms/blk
  Verify block proofs/scripts                       155.1s     3.91 ms/blk
  BLSCT aggregate signatures                        145.2s     3.66 ms/blk
  BLSCT reward/stake tx collect                       7.5s     0.19 ms/blk
  Write undo data                                     0.2s     0.01 ms/blk
  BLSCT block rangeproof batch (all sizes)          106.7s     2.69 ms/blk
  PoS setmem (async worker CPU, summed)              70.3s     1.77 ms/blk
```

(`Connect block` ≈ wall: the reindex is validation-bound. "PoS setmem" runs on
the async verifier thread and overlaps with the rest, so it is CPU time, not
critical-path time. Aggregate signatures get *slower* with OpenMP because the
library's std::async workers now contend with OpenMP's pool.)

blst cannot be run through the node yet (the wallet/PoS/signature glue still
names `MclG1Point`, see below), so its full-sync figure is a projection: the
measured per-block crypto buckets are scaled by the ratios measured on this
host for exactly those operations (`RPVerify4` for the 2–5-proof batches,
`AggVerify2`, `SetMemVerify16`); everything else per block is kept as
measured.

| build | measured ms/blk | range proofs ms/blk (mcl → blst) | agg. signatures (mcl → blst) | PoS setmem CPU (mcl → blst) | projected blst ms/blk |
|---|---:|---:|---:|---:|---:|
| mcl (release config, no OpenMP) → blst, MSM single-threaded | 14.41 | 6.69 → 2.78 (2.41×) | 3.05 → 0.95 (3.22×) | 2.48 → 0.99 (2.50×) | **8.40** (1.72× faster, 571 s → 333 s) |
| mcl (release config, no OpenMP) → blst, MSM tiled over threads | 14.41 | 6.69 → 1.79 (3.74×) | 3.05 → 0.95 (3.22×) | 2.48 → 0.47 (5.30×) | **7.41** (1.95× faster, 571 s → 294 s) |
| mcl + OpenMP → blst, MSM tiled over threads | 11.28 | 2.69 → 1.15 (2.34×) | 3.66 → 1.14 (3.22×) | 1.77 → 0.46 (3.84×) | **7.22** (1.56× faster, 447 s → 286 s) |

In short (projection): ~1.7–2× faster full sync in the release
configuration, and still ~1.5× faster than an OpenMP mcl build.

#### Measured after the migration

With mcl removed and the node running on blst (same host, same datadir,
`contrib/devtools/blsct-sync-bench.sh build/bin/naviod build/bin/navio-cli
<datadir>`), the reindex reproduces the mcl tip hash
(`9e0ab3878d39106c3753c2b51b97d3961f2d4a5cd799ee05826a414c0e0d7e1f` at
39,645) and measures:

```
reindex-chainstate to height 39645: 435.5s wall (10.98 ms/block)   [2nd run: 466.7s]
  Connect block                                     429.8s    10.84 ms/blk
  Verify block proofs/scripts                       324.0s     8.17 ms/blk
  BLSCT aggregate signatures                        105.2s     2.65 ms/blk
  BLSCT block rangeproof batch (all sizes)          305.4s     7.70 ms/blk
  PoS setmem (async worker CPU, summed)             144.1s     3.63 ms/blk
```

Repeated on the same machine once it was quiet again (load average ~3),
mcl and blst back-to-back on the same datadir:

| node | wall | ms/blk | range proofs | agg. sigs | PoS setmem (CPU) |
|---|---:|---:|---:|---:|---:|
| mcl (release config, no OpenMP) | 552 s | 13.9 | 6.9 | 3.0 | 2.5 |
| **blst (this tree)** | **163 s** | **4.1** | 2.9 | 0.9 | 1.4 |

i.e. **3.4× faster full sync**, tip hash identical. (Two earlier blst runs at
435–467 s and an mcl run at 1480 s were taken while the machine carried an
unrelated desktop workload; they are only comparable to each other.) The
fixed-base generator precompute that follows this migration takes the blst
figure to 151 s on this host.

## Migration assessment

### What a real migration touches

| Area | Size | Notes |
|---|---|---|
| Arith wrappers | done here (~900 lines in `src/blsct/arith/blst/`) | Production port still needs the `SubgroupCheckDeferralScope` / `SkipScope` / `LegacyPointDecodeScope` thread-local machinery (mechanical), and a decision on `IsValid()` semantics. With blst the deferral scope loses its purpose: `blst_p1_in_g1` is ~40 µs vs mcl's ~73 µs and, more importantly, the decode itself no longer hides a second order check. |
| Templated proof code | 1 line (`Run<Mcl>` → `Run<T>`) | Already generic. The 20 gated instantiation blocks become the *only* instantiations once mcl is dropped. |
| Direct users of `MclG1Point` / `MclScalar` / `Mcl` | 88 non-test files (wallet 16, pos 8, node/txdb 3, external API 2, ...) + 37 test files | Almost all are `using Point = MclG1Point;` style aliases → a single `blsct::Arith` alias swap; `pos/proof.h`, `txdb.cpp`, `blockstorage.cpp` use the deferral scopes. |
| Signature layer | `signature.cpp`, `public_key(s).cpp`, `private_key.cpp` (16 C-API calls) | Replace `blsSign` / `blsVerify` / `blsAggregateSignature` / `blsAggregateVerifyNoCheck` with `blst_sign_pk_in_g1`, `blst_core_verify_pk_in_g1`, `blst_p2_add`, `blst_pairing_*` — exactly what the `SigFixture` in the bench does, incl. the per-thread context merge that replaces the std::async patch inside the vendored bls library. |
| EIP-2333 keygen, `Elements`, `GeneratorDeriver`, Fiat–Shamir | 0 | Already generic (instantiated and cross-checked here). |
| Build | `cmake/blst.cmake` (FetchContent, evaluation only) | For release/guix builds vendor the pinned source (one `server.c` + one pre-generated `assembly.S` per platform; no perl needed at build time) as a `depends` package or `src/blst/` and compile it from CMake directly; MSVC has `build/win64/*.asm` (`build.bat`). Drops the mcl+bls GNU-Makefile `ExternalProject`, the `MCL_USE_LLVM`/`LLVM_OPT_VERSION` workarounds, the OpenMP option and libomp. |
| Platforms | — | x86_64 (ADX and non-ADX paths selected at runtime via `cpuid`, so one guix binary serves both), arm64 assembly, portable C (`-D__BLST_PORTABLE__` / `__BLST_NO_ASM__`) for everything else incl. 32-bit — the i686 CI job must be validated. |
| Differential testing | `blst_equivalence_tests` + bench cross-checks | Before flipping the default: a fuzz target that feeds both backends the same encodings / proofs and asserts identical accept/reject (the only place two correct libraries can legitimately differ is *which malformed inputs they reject*), a full testnet sync and a mainnet `-reindex-chainstate` under each backend with identical tip hash. |

### Risks / trade-offs

* **Consensus surface is decode acceptance, not values.** Every value-producing
  operation is bit-identical (verified). Acceptance of *malformed* encodings
  (x ≥ p, non-canonical infinity, sign bit on infinity, scalars ≥ r) is
  where two libraries can differ; the checked-decode path agreed on all
  random/off-subgroup/bad encodings tried here, but this must be closed with
  a differential fuzzer, not sampling.
* **Library posture.** blst: Apache-2.0, C + assembly, constant-time, NCC
  Group audit (2021), the BLS library of every Ethereum consensus client;
  releases are infrequent and conservative. mcl: BSD-3, C++ templates with
  a large multi-curve surface and its own bignum/JIT layers, and navio
  carries local patches to the vendored bls (`blsAggregateVerifyNoCheck`
  threading). blst removes the OpenMP runtime and the libomp/`std::async`
  interaction that motivated `pos_async_verifier.h`.
* **API shape.** blst is a flat C API over opaque structs with no string
  I/O, no generic `mod p` reduction and no threading; the wrapper has to
  provide those (done here, ~100 lines). Debug string formats (`GetString`)
  were reproduced but are not consensus.
* **Two libraries during transition.** Keeping mcl compiled (behind the
  existing `WITH_BLST`-style gate, inverted) for a release cycle as a
  differential oracle in tests costs nothing at runtime and is the safest
  route to flipping the default.

### Recommendation

Proceed with the migration, staged:

1. Merge this scaffolding (default OFF, no behaviour change). CI job with
   `-DWITH_BLST=ON` running `blst_equivalence_tests` and the `BLSCTCmp_*`
   sanity pass.
2. Port the remaining pieces above (deferral scopes, signature layer, alias
   swap), add the differential fuzz target, vendor blst for guix, validate
   i686/portable and Windows.
3. Flip the default in a release after a testnet sync + mainnet
   `-reindex-chainstate` under blst reproduce the mcl tip hash; keep mcl
   test-only for one release.
4. Remove mcl/bls, OpenMP, `FixedBaseCache` (the fixed-base window
   precompute it prototypes is what blst's `blst_p1s_mult_wbits_precompute`
   already provides for the Gi/Hi generators — a further win not measured
   here).
