// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Benchmark: batched vs per-item PoS set-membership proof verification.
//
// Each set-membership proof reduces to checking one multi-scalar multiplication
// == identity, over a set of per-proof commitments (Ys) AND the shared setup.hs
// generators (N up to 1024). SetMemProofProver::VerifyBatch folds B proofs into
// one accumulator under Fiat-Shamir random weights, so the shared generators are
// multiplied once for the whole batch instead of once per proof — the dominant
// saving during a staking-chain sync, where one such proof is verified per block.
//
// This compares, for B proofs sharing a set size:
//   PerItem  - B independent SetMemProofProver::Verify calls (current path).
//   Batch    - one SetMemProofProver::VerifyBatch over all B.

#include <bench/bench.h>

#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_init.h>
#include <blsct/set_mem_proof/set_mem_proof.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <blsct/set_mem_proof/set_mem_proof_setup.h>
#include <ctokens/tokenid.h>

#include <string>
#include <vector>

namespace {

using Arith = Mcl;
using Point = Arith::Point;
using Scalar = Arith::Scalar;
using Points = Elements<Point>;
using Prover = SetMemProofProver<Arith>;

struct Sample {
    Points Ys;
    Scalar eta_fiat_shamir;
    blsct::Message eta_phi;
    SetMemProof<Arith> proof;
};

struct BatchFixture {
    std::vector<Sample> samples;

    BatchFixture(size_t batch, size_t set_size)
    {
        volatile MclInit mcl_init;
        (void)mcl_init;

        const auto& setup = SetMemProofSetup<Arith>::Get();
        samples.reserve(batch);
        for (size_t b = 0; b < batch; ++b) {
            range_proof::Generators<Arith> gen = setup.Gf().GetInstance(TokenId());
            Scalar m = Scalar::Rand();
            Scalar f = Scalar::Rand();
            auto sigma = gen.G * m + gen.H * f;

            Points Ys;
            const size_t member_idx = b % set_size;
            for (size_t i = 0; i < set_size; ++i) {
                if (i == member_idx) {
                    Ys.Add(sigma);
                } else {
                    Ys.Add(Point::MapToPoint("y" + std::to_string(b) + "_" + std::to_string(i),
                                             Endianness::Little));
                }
            }
            Scalar eta = Scalar::Rand();
            blsct::Message phi{uint8_t(b), uint8_t(b + 1), uint8_t(b + 2)};
            auto proof = Prover::Prove(setup, Ys, sigma, m, f, eta, phi);
            samples.push_back(Sample{Ys, eta, phi, proof});
        }
    }

    std::vector<Prover::VerifyBatchItem> Items() const
    {
        std::vector<Prover::VerifyBatchItem> items;
        items.reserve(samples.size());
        for (const auto& s : samples) items.push_back({&s.Ys, s.eta_fiat_shamir, s.eta_phi, &s.proof});
        return items;
    }
};

void RunPerItem(benchmark::Bench& bench, size_t batch, size_t set_size)
{
    BatchFixture fx(batch, set_size);
    const auto& setup = SetMemProofSetup<Arith>::Get();
    bench.batch(batch).unit("proof").run([&] {
        bool ok = true;
        for (const auto& s : fx.samples) {
            ok &= Prover::Verify(setup, s.Ys, s.eta_fiat_shamir, s.eta_phi, s.proof);
        }
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

void RunBatch(benchmark::Bench& bench, size_t batch, size_t set_size)
{
    BatchFixture fx(batch, set_size);
    const auto& setup = SetMemProofSetup<Arith>::Get();
    auto items = fx.Items();
    bench.batch(batch).unit("proof").run([&] {
        bool ok = Prover::VerifyBatch(setup, items);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

constexpr size_t kSetSize = 128; // padded anonymity-set size per proof

} // namespace

static void BLSCTSetMemPerItem_8(benchmark::Bench& b)   { RunPerItem(b, 8, kSetSize); }
static void BLSCTSetMemBatch_8(benchmark::Bench& b)     { RunBatch(b, 8, kSetSize); }
static void BLSCTSetMemPerItem_32(benchmark::Bench& b)  { RunPerItem(b, 32, kSetSize); }
static void BLSCTSetMemBatch_32(benchmark::Bench& b)    { RunBatch(b, 32, kSetSize); }
static void BLSCTSetMemPerItem_128(benchmark::Bench& b) { RunPerItem(b, 128, kSetSize); }
static void BLSCTSetMemBatch_128(benchmark::Bench& b)   { RunBatch(b, 128, kSetSize); }

BENCHMARK(BLSCTSetMemPerItem_8,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTSetMemBatch_8,     benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTSetMemPerItem_32,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTSetMemBatch_32,    benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTSetMemPerItem_128, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTSetMemBatch_128,   benchmark::PriorityLevel::HIGH);
