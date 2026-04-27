# Building with GMP

Navio Core uses [herumi/mcl](https://github.com/herumi/mcl) for the BLS12-381
curve arithmetic that underpins BLSCT (Confidential Transactions, BLS
signatures, range proofs). `mcl` can use either its internal `VINT` big-integer
backend or the [GNU Multiple Precision Arithmetic Library (GMP)](https://gmplib.org/).
The GMP path is significantly faster for inversion-heavy operations and is
recommended for any production or validating node.

The build system auto-detects GMP when present and falls back to `VINT` when
it is missing.

## Installing GMP

| OS | Command |
| --- | --- |
| Debian / Ubuntu | `sudo apt install libgmp-dev` |
| Fedora / RHEL | `sudo dnf install gmp-devel gmp-c++` |
| Arch | `sudo pacman -S gmp` |
| Alpine | `sudo apk add gmp-dev` |
| FreeBSD | `pkg install gmp` |
| macOS (Homebrew) | `brew install gmp` |
| `depends/` builds | Built automatically; no action required |

## Configure flags

| Flag | Behaviour |
| --- | --- |
| _(default)_ | Auto-detect; use GMP if found, otherwise fall back to `VINT`. |
| `--with-gmp` | Hard-require GMP. Configure fails if not found. |
| `--without-gmp` | Force the `VINT` fallback even if GMP is installed. |

You can confirm the active backend by inspecting the configure output line
`checking whether to build mcl with GMP`, or by running `ldd` against `naviod`
and looking for `libgmp.so` and `libgmpxx.so`.

## Benchmark: VINT vs GMP

Numbers from `src/bls/mcl/bin/bls12_test.exe` on Linux x86_64. Same source, only
`MCL_USE_GMP` differs. Lower clk count is better.

### Hot field operations — no change

These paths are already implemented in hand-written assembly, so the choice of
big-integer backend does not affect them.

| Operation | VINT | GMP |
| --- | ---: | ---: |
| Fp::add | 13.47 clk | 11.86 clk |
| Fp::mul | 80.02 clk | 80.04 clk |
| Fp::sqr | 90.07 clk | 90.17 clk |
| Fr::mul | 48.14 clk | 48.27 clk |
| Fp2::mul | 221.80 clk | 221.43 clk |
| pairing | 1.377 Mclk | 1.373 Mclk |
| millerLoop | 574.5 Kclk | 572.5 Kclk |
| finalExp | 791.2 Kclk | 797.9 Kclk |
| G1::mul | 164.1 Kclk | 160.5 Kclk |
| G2::mul | 285.6 Kclk | 281.0 Kclk |

### Inversion and bignum-heavy paths — large wins with GMP

| Operation | VINT | GMP | Speedup |
| --- | ---: | ---: | ---: |
| Fp::inv | 12.752 Kclk | 6.694 Kclk | **1.91×** |
| Fp2::inv | 13.081 Kclk | 6.864 Kclk | **1.91×** |
| GT::inv | 13.806 Kclk | 10.467 Kclk | 1.32× |
| hashAndMapToG1 | 261.260 Kclk | 178.116 Kclk | **1.47×** |
| hashAndMapToG2 | 473.112 Kclk | 347.242 Kclk | **1.36×** |
| deserializeG1 (verifyOrder) | 211.836 Kclk | 170.637 Kclk | 1.24× |
| deserializeG2 (verifyOrder) | 303.054 Kclk | 210.098 Kclk | **1.44×** |
| deserializeG1 (no verify) | 86.959 Kclk | 45.624 Kclk | **1.91×** |
| deserializeG2 (no verify) | 187.764 Kclk | 94.518 Kclk | **1.99×** |
| BLS12_381 multi-pairing calcBN1 | 137.500 Kclk | 61.798 Kclk | **2.22×** |
| BLS12_381 multi-pairing calcBN2 | 299.182 Kclk | 126.407 Kclk | **2.37×** |
| BLS12_381 multi naiveG2 | 180.141 Kclk | 99.664 Kclk | **1.81×** |

## End-to-end benchmark on `bench_navio`

The mcl micro-benchmark above measures isolated field operations. The
practical question is how much GMP shifts real BLSCT workloads in
`bench_navio`. Numbers below are median ns/op from `bench_navio
-filter=BLSCT.* -min-time=3000`, same hardware, only `--with-gmp` /
`--without-gmp` differs.

| Bench | VINT (ns/op) | GMP (ns/op) | Speedup |
| --- | ---: | ---: | ---: |
| BLSCTPointSerialize | 1,620.6 | 853.2 | **1.90×** |
| BLSCTPointDeserialize | 49,480.2 | 40,088.4 | **1.23×** |
| BLSCTHashAndMapG1 | 40,197.8 | 38,585.5 | 1.04× |
| BLSCTAggregateSignVerify4 | 1,952,949.2 | 1,881,309.7 | 1.04× |
| BLSCTRangeProofVerifyBatch4 | 3,043,202.8 | 2,942,935.4 | 1.03× |
| BLSCTVerify | 559,588.8 | 550,937.6 | 1.02× |
| BLSCTSign | 193,573.8 | 190,879.2 | 1.01× |
| BLSCTScalarInvert | 1,107.8 | 1,097.2 | 1.01× |
| BLSCTRangeProofProve | 16,183,202.5 | 16,120,047.0 | 1.00× |
| BLSCTRangeProofVerify | 2,767,747.1 | 2,811,486.5 | 0.98× |

### Reading the numbers

- **Point (de)serialization sees the headline wins (1.2–1.9×).** These paths
  call `Fp::inv` directly per point, and `Fp::inv` is the operation where
  GMP's faster bignum arithmetic actually lands.
- **Signing, verification, and range-proof prove/verify barely move (0–4%).**
  Their hot loops are dominated by field multiplication, squaring, and the
  pairing — all hand-written assembly, where the bignum backend is irrelevant.
  Modular inversion is rare on these paths, so its 1.9× speedup does not
  translate to the workload total.
- **`BLSCTScalarInvert` is unchanged (1.01×).** Scalar (`Fr`) inversion is
  not a GMP-sensitive path; only field (`Fp`) inversion is.

### Bottom line

GMP is worth enabling. The wins are concentrated on point (de)serialization
— hit on every block validation, every transaction with a BLSCT input, and
every wire-format read — where it gives a 1.2–1.9× speedup. Headline crypto
operations (sign / verify / range proof) see ~0–4%, which is still a free
improvement at no cost beyond installing one development package. The mcl
micro-benchmark above shows where the underlying speedup comes from; the
navio benchmark above shows what it actually buys you.

## Reproducing the benchmark

mcl micro-benchmark:

```sh
cd src/bls/mcl
make clean && make MCL_USE_GMP=1 bin/bls12_test.exe && ./bin/bls12_test.exe
make clean && make MCL_USE_GMP=0 bin/bls12_test.exe && ./bin/bls12_test.exe
```

navio end-to-end benchmark:

```sh
./configure --with-gmp && make && \
  src/bench/bench_navio -filter='BLSCT.*' -min-time=3000 -output-csv=gmp.csv

./configure --without-gmp && make && \
  src/bench/bench_navio -filter='BLSCT.*' -min-time=3000 -output-csv=vint.csv
```
