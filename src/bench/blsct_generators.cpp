// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_init.h>
#include <blsct/range_proof/generators.h>
#include <ctokens/tokenid.h>

using Arith = Mcl;

// GeneratorsFactory::GetInstance is called once per transaction input, per
// output and per range proof on the block-connect / mempool-accept verify path
// (blsct::VerifyTx balance accumulation + range-proof verify). Most of those
// call sites use only the derived `G` generator, yet each call used to deep-copy
// the shared 1024-point Gi/Hi tables (~294 KB each). This microbenchmark isolates
// the per-call cost.
static void BLSCTGeneratorsGetInstance(benchmark::Bench& bench)
{
    volatile MclInit init;
    (void)init;

    range_proof::GeneratorsFactory<Arith> gf;
    const TokenId token_id;

    bench.unit("GetInstance").run([&] {
        auto gens = gf.GetInstance(token_id);
        ankerl::nanobench::doNotOptimizeAway(gens.G);
    });
}

BENCHMARK(BLSCTGeneratorsGetInstance, benchmark::PriorityLevel::HIGH);
