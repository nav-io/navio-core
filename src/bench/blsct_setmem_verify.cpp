// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_init.h>
#include <blsct/pos/helpers.h>
#include <blsct/pos/proof.h>
#include <blsct/range_proof/generators.h>
#include <blsct/set_mem_proof/set_mem_proof.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <blsct/set_mem_proof/set_mem_proof_setup.h>

#include <stdexcept>
#include <string>
#include <vector>

using Arith = Mcl;
using Point = Arith::Point;
using Scalar = Arith::Scalar;
using Points = Elements<Point>;
using Prover = SetMemProofProver<Arith>;

namespace {

// Build a valid SetMemProof over `n` staked-commitment points. `sigma` is
// inserted at the first index so the indicator bL has weight 1, matching
// the realistic PoS shape (the staker reveals one of n commitments).
struct SetMemFixture {
    Points Ys;
    Scalar m;
    Scalar f;
    Scalar eta_fiat_shamir;
    blsct::Message eta_phi{1, 2, 3};
    SetMemProof<Arith> proof;

    explicit SetMemFixture(size_t n)
    {
        volatile MclInit init;
        (void)init;

        const auto& setup = SetMemProofSetup<Arith>::Get();
        auto gen = setup.Gf().GetInstance(TokenId());

        m = Scalar::Rand(true);
        f = Scalar::Rand(true);
        Point sigma = gen.G * m + gen.H * f;
        eta_fiat_shamir = Scalar::Rand(true);

        Ys.Add(sigma);
        for (size_t i = 1; i < n; ++i) {
            std::string seed = "bench_setmem_y_" + std::to_string(i);
            Ys.Add(Point::MapToPoint(seed, Endianness::Little));
        }

        proof = Prover::Prove(setup, Ys, sigma, m, f, eta_fiat_shamir, eta_phi);
    }
};

void BenchSetMemVerify(benchmark::Bench& bench, size_t n)
{
    SetMemFixture fx(n);
    const auto& setup = SetMemProofSetup<Arith>::Get();

    bench.unit("setmem-verify").run([&] {
        bool ok = Prover::Verify(setup, fx.Ys, fx.eta_fiat_shamir, fx.eta_phi, fx.proof);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

void BenchSetMemProve(benchmark::Bench& bench, size_t n)
{
    SetMemFixture fx(n);
    const auto& setup = SetMemProofSetup<Arith>::Get();

    bench.unit("setmem-prove").run([&] {
        auto p = Prover::Prove(setup, fx.Ys, fx.Ys.m_vec[0], fx.m, fx.f,
                               fx.eta_fiat_shamir, fx.eta_phi);
        ankerl::nanobench::doNotOptimizeAway(p.t);
    });
}

// End-to-end PoPS fixture: builds a real ProofOfStake (set-mem proof + range
// proof of the staked value) for a set of size `n`. Uses next_target=0 so the
// derived min_value is 0, which makes any positive `m` satisfiable by the
// range proof — this isolates the cryptographic cost from any kernel-hash
// search (which is the staker's grinding cost, not the verifier's).
struct PoPSFixture {
    Points staked_commitments;
    Scalar eta_fiat_shamir;
    blsct::Message eta_phi{1, 2, 3};
    uint32_t prev_time{1714000000};
    uint64_t stake_modifier{0xdeadbeefcafef00dULL};
    uint32_t time{1714000060};
    unsigned int next_target{0};
    uint256 kernel_hash;
    blsct::ProofOfStake proof;

    explicit PoPSFixture(size_t n)
    {
        volatile MclInit init;
        (void)init;

        const auto& setup = SetMemProofSetup<Arith>::Get();
        auto gen = setup.Gf().GetInstance(TokenId());

        Scalar m(int64_t{1000000});  // any positive value is fine when next_target=0
        Scalar f = Scalar::Rand(true);
        Point sigma = gen.G * m + gen.H * f;
        eta_fiat_shamir = Scalar::Rand(true);

        staked_commitments.Add(sigma);
        for (size_t i = 1; i < n; ++i) {
            std::string seed = "bench_pops_y_" + std::to_string(i);
            staked_commitments.Add(Point::MapToPoint(seed, Endianness::Little));
        }

        proof = blsct::ProofOfStake(staked_commitments, eta_fiat_shamir, eta_phi,
                                    m, f, prev_time, stake_modifier, time, next_target);
        kernel_hash = blsct::CalculateKernelHash(prev_time, stake_modifier, time);

        // Sanity: refuse to bench a proof that doesn't actually verify.
        // Otherwise we'd silently measure an early-exit short-circuit and
        // mis-report the cost of the verify pipeline.
        auto check = proof.Verify(staked_commitments, eta_fiat_shamir, eta_phi,
                                  kernel_hash, next_target);
        if (check != blsct::ProofOfStake::VALID) {
            throw std::runtime_error(std::string("PoPSFixture: constructed proof did not verify, result=") +
                                     blsct::ProofOfStake::VerificationResultToString(check));
        }
    }
};

void BenchPoPSVerify(benchmark::Bench& bench, size_t n)
{
    PoPSFixture fx(n);
    bench.unit("pops-verify").run([&] {
        auto res = fx.proof.Verify(fx.staked_commitments, fx.eta_fiat_shamir,
                                   fx.eta_phi, fx.kernel_hash, fx.next_target);
        ankerl::nanobench::doNotOptimizeAway(res);
    });
}

} // namespace

static void BLSCTPoPSSetMemVerify_2(benchmark::Bench& b)    { BenchSetMemVerify(b, 2); }
static void BLSCTPoPSSetMemVerify_4(benchmark::Bench& b)    { BenchSetMemVerify(b, 4); }
static void BLSCTPoPSSetMemVerify_8(benchmark::Bench& b)    { BenchSetMemVerify(b, 8); }
static void BLSCTPoPSSetMemVerify_16(benchmark::Bench& b)   { BenchSetMemVerify(b, 16); }
static void BLSCTPoPSSetMemVerify_32(benchmark::Bench& b)   { BenchSetMemVerify(b, 32); }
static void BLSCTPoPSSetMemVerify_64(benchmark::Bench& b)   { BenchSetMemVerify(b, 64); }
static void BLSCTPoPSSetMemVerify_128(benchmark::Bench& b)  { BenchSetMemVerify(b, 128); }
static void BLSCTPoPSSetMemVerify_256(benchmark::Bench& b)  { BenchSetMemVerify(b, 256); }
static void BLSCTPoPSSetMemVerify_512(benchmark::Bench& b)  { BenchSetMemVerify(b, 512); }
static void BLSCTPoPSSetMemVerify_1024(benchmark::Bench& b) { BenchSetMemVerify(b, 1024); }

static void BLSCTPoPSSetMemProve_2(benchmark::Bench& b)    { BenchSetMemProve(b, 2); }
static void BLSCTPoPSSetMemProve_16(benchmark::Bench& b)   { BenchSetMemProve(b, 16); }
static void BLSCTPoPSSetMemProve_64(benchmark::Bench& b)   { BenchSetMemProve(b, 64); }
static void BLSCTPoPSSetMemProve_256(benchmark::Bench& b)  { BenchSetMemProve(b, 256); }
static void BLSCTPoPSSetMemProve_1024(benchmark::Bench& b) { BenchSetMemProve(b, 1024); }

static void BLSCTPoPSVerify_2(benchmark::Bench& b)    { BenchPoPSVerify(b, 2); }
static void BLSCTPoPSVerify_4(benchmark::Bench& b)    { BenchPoPSVerify(b, 4); }
static void BLSCTPoPSVerify_8(benchmark::Bench& b)    { BenchPoPSVerify(b, 8); }
static void BLSCTPoPSVerify_16(benchmark::Bench& b)   { BenchPoPSVerify(b, 16); }
static void BLSCTPoPSVerify_32(benchmark::Bench& b)   { BenchPoPSVerify(b, 32); }
static void BLSCTPoPSVerify_64(benchmark::Bench& b)   { BenchPoPSVerify(b, 64); }
static void BLSCTPoPSVerify_128(benchmark::Bench& b)  { BenchPoPSVerify(b, 128); }
static void BLSCTPoPSVerify_256(benchmark::Bench& b)  { BenchPoPSVerify(b, 256); }
static void BLSCTPoPSVerify_512(benchmark::Bench& b)  { BenchPoPSVerify(b, 512); }
static void BLSCTPoPSVerify_1024(benchmark::Bench& b) { BenchPoPSVerify(b, 1024); }

BENCHMARK(BLSCTPoPSSetMemVerify_2,    benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemVerify_4,    benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemVerify_8,    benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemVerify_16,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemVerify_32,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemVerify_64,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemVerify_128,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemVerify_256,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemVerify_512,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemVerify_1024, benchmark::PriorityLevel::HIGH);

BENCHMARK(BLSCTPoPSSetMemProve_2,    benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemProve_16,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemProve_64,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemProve_256,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSSetMemProve_1024, benchmark::PriorityLevel::HIGH);

BENCHMARK(BLSCTPoPSVerify_2,    benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSVerify_4,    benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSVerify_8,    benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSVerify_16,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSVerify_32,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSVerify_64,   benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSVerify_128,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSVerify_256,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSVerify_512,  benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPoPSVerify_1024, benchmark::PriorityLevel::HIGH);
