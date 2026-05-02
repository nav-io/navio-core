// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_init.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <ctokens/tokenid.h>

#include <vector>

using Arith = Mcl;
using RP = bulletproofs_plus::RangeProofLogic<Arith>;
using Proof = bulletproofs_plus::RangeProofWithSeed<Arith>;
using Scalar = Mcl::Scalar;
using Point = Mcl::Point;
using Scalars = Elements<Scalar>;

namespace {

// Build `n` distinct valid range proofs by calling RangeProofLogic::Prove on
// a fresh random nonce per proof. Uses a shared RangeProofLogic instance —
// the ctor/factory init is guarded but we keep the hot object alive anyway.
std::vector<Proof> MakeProofs(size_t n)
{
    volatile MclInit init;
    (void)init;

    static RP rp;
    std::vector<Proof> out;
    out.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        Scalars vs;
        vs.Add(Scalar(1000 + i));

        Scalar nonce_scalar = Scalar::Rand(true);
        Scalars nonce_seed;
        nonce_seed.Add(nonce_scalar);
        range_proof::GammaSeed<Arith> nonce(nonce_seed);

        std::vector<uint8_t> msg(8, 0);
        bulletproofs_plus::RangeProof<Arith> raw = rp.Prove(vs, nonce, msg, TokenId());
        out.emplace_back(raw, TokenId());
    }
    return out;
}

void BenchVerify(benchmark::Bench& bench, size_t n)
{
    volatile MclInit init;
    (void)init;

    auto proofs = MakeProofs(n);
    RP rp;

    bench.batch(n).unit("rp-verify").run([&] {
        bool ok = rp.Verify(proofs);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

} // namespace

static void BLSCTRPVerify_1(benchmark::Bench& b)  { BenchVerify(b, 1); }
static void BLSCTRPVerify_2(benchmark::Bench& b)  { BenchVerify(b, 2); }
static void BLSCTRPVerify_4(benchmark::Bench& b)  { BenchVerify(b, 4); }
static void BLSCTRPVerify_8(benchmark::Bench& b)  { BenchVerify(b, 8); }
static void BLSCTRPVerify_16(benchmark::Bench& b) { BenchVerify(b, 16); }
static void BLSCTRPVerify_32(benchmark::Bench& b) { BenchVerify(b, 32); }

BENCHMARK(BLSCTRPVerify_1,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTRPVerify_2,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTRPVerify_4,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTRPVerify_8,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTRPVerify_16, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTRPVerify_32, benchmark::PriorityLevel::HIGH);
