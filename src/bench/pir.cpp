// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <node/pir.h>
#include <pir/simplepir.h>
#include <random.h>

#include <cstdlib>

// SimplePIR over output records (see node/pir.h): hint generation (server,
// once per epoch), answering one query (server, full database scan), query
// generation and answer decoding (client), for databases of 2^14 .. 2^22
// records of node::PIR_RECORD_BYTES. All single-threaded.
//
// Databases above 2^14 records take up to minutes and gigabytes to set up and
// hint, so they only run with NAVIO_BENCH_PIR_LARGE set in the environment:
//   NAVIO_BENCH_PIR_LARGE=1 bench_navio -filter='Pir.*'

namespace {

bool Enabled(int log2_records)
{
    return log2_records <= 14 || std::getenv("NAVIO_BENCH_PIR_LARGE") != nullptr;
}

pir::Params MakeParams(int log2_records)
{
    const uint32_t n{uint32_t{1} << log2_records};
    return {node::PIR_RECORD_BYTES, n, pir::ChooseRecordsPerCol(n)};
}

pir::Database RandomDatabase(const pir::Params& params)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    pir::Database db{params.record_bytes, params.records_per_col};
    db.Reserve(params.num_records);
    std::vector<uint8_t> rec(params.record_bytes);
    for (uint32_t i = 0; i < params.num_records; ++i) {
        rng.fillrand(MakeWritableByteSpan(rec));
        db.Append(rec);
    }
    return db;
}

void HintGen(benchmark::Bench& bench, int log2_records)
{
    if (!Enabled(log2_records)) return;
    const pir::Database db{RandomDatabase(MakeParams(log2_records))};
    const uint256 seed{uint256::ONE};
    if (log2_records >= 18) bench.epochs(1).epochIterations(1);
    bench.unit("hint").run([&] {
        const pir::Hint hint{pir::ComputeHint(db, seed)};
        ankerl::nanobench::doNotOptimizeAway(hint[0]);
    });
}

void ServerAnswer(benchmark::Bench& bench, int log2_records)
{
    if (!Enabled(log2_records)) return;
    const pir::Params params{MakeParams(log2_records)};
    const pir::Database db{RandomDatabase(params)};
    FastRandomContext rng{/*fDeterministic=*/true};
    std::vector<uint32_t> query(params.Cols());
    for (auto& q : query) q = rng.rand32();
    if (log2_records >= 20) bench.epochs(3).epochIterations(1);
    bench.unit("query").run([&] {
        auto answer{pir::Answer(db, query, params.num_records)};
        ankerl::nanobench::doNotOptimizeAway((*answer)[0]);
    });
}

void ClientQuery(benchmark::Bench& bench, int log2_records)
{
    if (!Enabled(log2_records)) return;
    const pir::Params params{MakeParams(log2_records)};
    FastRandomContext rng{/*fDeterministic=*/true};
    const uint256 seed{uint256::ONE};
    uint32_t index{0};
    if (log2_records >= 20) bench.epochs(3).epochIterations(1);
    bench.unit("query").run([&] {
        pir::QueryState state;
        auto query{pir::MakeQuery(params, seed, index, rng, state)};
        index = (index + 7919) % params.num_records;
        ankerl::nanobench::doNotOptimizeAway((*query)[0]);
    });
}

void ClientDecode(benchmark::Bench& bench, int log2_records)
{
    if (!Enabled(log2_records)) return;
    const pir::Params params{MakeParams(log2_records)};
    FastRandomContext rng{/*fDeterministic=*/true};
    // Decoding cost does not depend on the hint's or answer's contents.
    pir::Hint hint(size_t{params.Rows()} * pir::LWE_N);
    for (auto& h : hint) h = rng.rand32();
    std::vector<uint32_t> answer(params.Rows());
    for (auto& a : answer) a = rng.rand32();
    pir::QueryState state;
    state.params = params;
    state.index = params.num_records - 1;
    state.secret.resize(pir::LWE_N);
    for (auto& s : state.secret) s = rng.rand32();
    bench.unit("record").run([&] {
        auto record{pir::Decode(state, hint, answer)};
        ankerl::nanobench::doNotOptimizeAway((*record)[0]);
    });
}

#define PIR_BENCHES(LOG2)                                                                  \
    static void PirHintGen_2p##LOG2(benchmark::Bench& bench) { HintGen(bench, LOG2); }     \
    static void PirServerAnswer_2p##LOG2(benchmark::Bench& bench) { ServerAnswer(bench, LOG2); } \
    static void PirClientQuery_2p##LOG2(benchmark::Bench& bench) { ClientQuery(bench, LOG2); } \
    static void PirClientDecode_2p##LOG2(benchmark::Bench& bench) { ClientDecode(bench, LOG2); } \
    BENCHMARK(PirHintGen_2p##LOG2, benchmark::PriorityLevel::LOW);                         \
    BENCHMARK(PirServerAnswer_2p##LOG2, benchmark::PriorityLevel::LOW);                    \
    BENCHMARK(PirClientQuery_2p##LOG2, benchmark::PriorityLevel::LOW);                     \
    BENCHMARK(PirClientDecode_2p##LOG2, benchmark::PriorityLevel::LOW);

PIR_BENCHES(14)
PIR_BENCHES(16)
PIR_BENCHES(18)
PIR_BENCHES(20)
PIR_BENCHES(22)

} // namespace
