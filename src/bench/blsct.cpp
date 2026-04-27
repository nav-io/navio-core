// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_init.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/public_keys.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/range_proof/common.h>
#include <ctokens/tokenid.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

using T = Mcl;
using Point = T::Point;
using Scalar = T::Scalar;
using Scalars = Elements<Scalar>;
using RangeProofLogic = bulletproofs_plus::RangeProofLogic<T>;
using RangeProofWithSeed = bulletproofs_plus::RangeProofWithSeed<T>;

namespace {

void EnsureMclInit()
{
    static const MclInit init;
}

Point MakeNonce()
{
    static const std::string s{"bench-nonce"};
    return Point::HashAndMap(std::vector<uint8_t>{s.begin(), s.end()});
}

TokenId MakeTokenId() { return TokenId(uint256(uint64_t{42})); }

Scalars MakeValues(size_t n)
{
    Scalars vs;
    for (size_t i = 0; i < n; ++i) vs.Add(Scalar(static_cast<int64_t>(1000 + i)));
    return vs;
}

} // namespace

static void BLSCTSign(benchmark::Bench& bench)
{
    EnsureMclInit();
    blsct::PrivateKey sk(1);
    const std::vector<uint8_t> msg{'b', 'e', 'n', 'c', 'h'};
    bench.unit("sign").run([&] {
        auto sig = sk.Sign(msg);
        ankerl::nanobench::doNotOptimizeAway(sig);
    });
}

static void BLSCTVerify(benchmark::Bench& bench)
{
    EnsureMclInit();
    blsct::PrivateKey sk(1);
    auto pk = sk.GetPublicKey();
    const std::vector<uint8_t> msg{'b', 'e', 'n', 'c', 'h'};
    auto sig = sk.Sign(msg);
    bench.unit("verify").run([&] {
        bool ok = pk.Verify(msg, sig);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

static void BLSCTAggregateSignVerify4(benchmark::Bench& bench)
{
    EnsureMclInit();
    std::vector<blsct::PrivateKey> sks{
        blsct::PrivateKey(1),
        blsct::PrivateKey(12345),
        blsct::PrivateKey(67890),
        blsct::PrivateKey(424242),
    };
    blsct::PublicKeys pks(std::vector<blsct::PublicKey>{
        sks[0].GetPublicKey(), sks[1].GetPublicKey(),
        sks[2].GetPublicKey(), sks[3].GetPublicKey(),
    });
    std::vector<std::vector<uint8_t>> msgs{
        {'m', 's', 'g', '1'}, {'m', 's', 'g', '2'},
        {'m', 's', 'g', '3'}, {'m', 's', 'g', '4'},
    };
    std::vector<blsct::Signature> sigs{
        sks[0].Sign(msgs[0]), sks[1].Sign(msgs[1]),
        sks[2].Sign(msgs[2]), sks[3].Sign(msgs[3]),
    };
    auto aggr = blsct::Signature::Aggregate(sigs);
    bench.batch(4).unit("verify").run([&] {
        bool ok = pks.VerifyBatch(msgs, aggr);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

static void BLSCTRangeProofProve(benchmark::Bench& bench)
{
    EnsureMclInit();
    auto nonce = MakeNonce();
    auto token_id = MakeTokenId();
    const std::vector<uint8_t> msg{'r', 'p'};
    auto vs = MakeValues(1);
    RangeProofLogic rpl;
    bench.unit("prove").run([&] {
        auto p = rpl.Prove(vs, nonce, msg, token_id);
        ankerl::nanobench::doNotOptimizeAway(p);
    });
}

static void BLSCTRangeProofVerify(benchmark::Bench& bench)
{
    EnsureMclInit();
    auto nonce = MakeNonce();
    auto token_id = MakeTokenId();
    const std::vector<uint8_t> msg{'r', 'p'};
    auto vs = MakeValues(1);
    RangeProofLogic rpl;
    auto proof = rpl.Prove(vs, nonce, msg, token_id);
    std::vector<RangeProofWithSeed> proofs{RangeProofWithSeed(proof, token_id)};
    bench.unit("verify").run([&] {
        bool ok = rpl.Verify(proofs);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

static void BLSCTRangeProofVerifyBatch4(benchmark::Bench& bench)
{
    EnsureMclInit();
    auto nonce = MakeNonce();
    auto token_id = MakeTokenId();
    const std::vector<uint8_t> msg{'r', 'p'};
    RangeProofLogic rpl;
    std::vector<RangeProofWithSeed> proofs;
    for (int i = 0; i < 4; ++i) {
        Scalars vs;
        vs.Add(Scalar(static_cast<int64_t>(1000 + i)));
        proofs.emplace_back(rpl.Prove(vs, nonce, msg, token_id), token_id);
    }
    bench.batch(4).unit("verify").run([&] {
        bool ok = rpl.Verify(proofs);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

static void BLSCTHashAndMapG1(benchmark::Bench& bench)
{
    EnsureMclInit();
    std::vector<uint8_t> data(32, 0xab);
    bench.unit("hash").run([&] {
        // mutate so each iteration hashes a fresh input
        ++data[0];
        auto p = Point::HashAndMap(data);
        ankerl::nanobench::doNotOptimizeAway(p);
    });
}

static void BLSCTPointSerialize(benchmark::Bench& bench)
{
    EnsureMclInit();
    std::vector<uint8_t> data(32, 0x77);
    auto p = Point::HashAndMap(data);
    bench.unit("serialize").run([&] {
        auto v = p.GetVch();
        ankerl::nanobench::doNotOptimizeAway(v);
    });
}

static void BLSCTPointDeserialize(benchmark::Bench& bench)
{
    EnsureMclInit();
    std::vector<uint8_t> data(32, 0x55);
    auto p = Point::HashAndMap(data);
    auto vch = p.GetVch();
    bench.unit("deserialize").run([&] {
        Point q;
        bool ok = q.SetVch(vch);
        ankerl::nanobench::doNotOptimizeAway(ok);
        ankerl::nanobench::doNotOptimizeAway(q);
    });
}

static void BLSCTScalarInvert(benchmark::Bench& bench)
{
    EnsureMclInit();
    Scalar s(123456789);
    bench.unit("invert").run([&] {
        auto inv = s.Invert();
        // chain to keep input changing slightly without dominating cost
        s = s + Scalar(1);
        ankerl::nanobench::doNotOptimizeAway(inv);
    });
}

BENCHMARK(BLSCTSign, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTVerify, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTAggregateSignVerify4, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTRangeProofProve, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTRangeProofVerify, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTRangeProofVerifyBatch4, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTHashAndMapG1, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPointSerialize, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTPointDeserialize, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTScalarInvert, benchmark::PriorityLevel::HIGH);
