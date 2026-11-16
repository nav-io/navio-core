// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/double_public_key.h>
#include <blsct/wallet/txfactory_global.h>
#include <chainparams.h>
#include <crypto/common.h>
#include <node/pir.h>
#include <pir/simplepir.h>
#include <random.h>
#include <streams.h>
#include <test/util/pir.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <cmath>

using namespace pir;

namespace {

Database RandomDatabase(FastRandomContext& rng, uint32_t record_bytes, uint32_t num_records, uint32_t k)
{
    Database db{record_bytes, k};
    std::vector<uint8_t> rec(record_bytes);
    for (uint32_t i = 0; i < num_records; ++i) {
        for (auto& b : rec) b = uint8_t(rng.rand32());
        db.Append(rec);
    }
    return db;
}

//! Query record index against db (or its first num_records) with the given hint and check the decode.
void CheckFetch(const Database& db, const Hint& hint, const uint256& seed, uint32_t index, FastRandomContext& rng,
                std::optional<uint32_t> num_records = std::nullopt)
{
    pir::Params params{db.GetParams()};
    if (num_records) params.num_records = *num_records;
    QueryState state;
    auto query{MakeQuery(params, seed, index, *MakeSecretRngForTesting(rng.rand256()), state)};
    BOOST_REQUIRE(query);
    BOOST_CHECK_EQUAL(query->size(), params.Cols());
    auto answer{Answer(db, *query, params.num_records)};
    BOOST_REQUIRE(answer);
    BOOST_CHECK_EQUAL(answer->size(), params.Rows());
    auto record{Decode(state, hint, *answer)};
    BOOST_REQUIRE(record);
    const auto expected{db.Record(index)};
    BOOST_CHECK(std::equal(record->begin(), record->end(), expected.begin(), expected.end()));
}

blsct::DoublePublicKey RandomDestination()
{
    return blsct::DoublePublicKey{BlstG1Point::Rand(), BlstG1Point::Rand()};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pir_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(params_limits)
{
    BOOST_CHECK_EQUAL(ChooseRecordsPerCol(0), 1U);
    BOOST_CHECK_EQUAL(ChooseRecordsPerCol(1), 1U);
    BOOST_CHECK_EQUAL(ChooseRecordsPerCol(MAX_COLS), 1U);
    BOOST_CHECK_EQUAL(ChooseRecordsPerCol(MAX_COLS + 1), 2U);
    BOOST_CHECK_EQUAL(ChooseRecordsPerCol(2 * MAX_COLS), 2U);
    BOOST_CHECK_EQUAL(ChooseRecordsPerCol(2 * MAX_COLS + 1), 3U);

    BOOST_CHECK(!(pir::Params{0, 10, 1}.IsValid()));
    BOOST_CHECK(!(pir::Params{10, 10, 0}.IsValid()));
    BOOST_CHECK((pir::Params{MAX_ROWS, 1, 1}.IsValid()));
    BOOST_CHECK(!(pir::Params{MAX_ROWS + 1, 1, 1}.IsValid()));
    BOOST_CHECK(!(pir::Params{MAX_ROWS / 2, 1, 3}.IsValid()));
    BOOST_CHECK((pir::Params{1, MAX_COLS, 1}.IsValid()));
    BOOST_CHECK(!(pir::Params{1, MAX_COLS + 1, 1}.IsValid()));
    BOOST_CHECK((pir::Params{1, MAX_COLS + 1, 2}.IsValid()));
    // Rows overflowing uint32 must not wrap into validity.
    BOOST_CHECK(!(pir::Params{uint32_t{1} << 16, 1, uint32_t{1} << 16}.IsValid()));

    const pir::Params p{1152, 1000, 1};
    BOOST_CHECK_EQUAL(p.Cols(), 1000U);
    BOOST_CHECK_EQUAL(p.HintBytes(), uint64_t{1152} * LWE_N * 4);
    BOOST_CHECK_EQUAL(p.QueryBytes(), 4000U);
    BOOST_CHECK_EQUAL(p.AnswerBytes(), 1152U * 4);
    BOOST_CHECK_EQUAL((pir::Params{10, 7, 3}.Cols()), 3U);

    // Decryption failure needs more than a 14 standard deviation error.
    BOOST_CHECK(ErrorStdDevOverHalfDelta(MAX_COLS) < 1.0 / 14);
}

BOOST_AUTO_TEST_CASE(matrix_expansion)
{
    const uint256 seed{InsecureRand256()};
    // Rows of A are the FastRandomContext(seed) byte stream, read as LE words.
    FastRandomContext stream{seed};
    const auto bytes{stream.randbytes<unsigned char>(size_t{4} * LWE_N * 3)};
    std::vector<uint32_t> rows(size_t{3} * LWE_N);
    ExpandA(seed, 0, 3, rows.data());
    for (size_t i = 0; i < rows.size(); ++i) {
        BOOST_REQUIRE_EQUAL(rows[i], ReadLE32(bytes.data() + 4 * i));
    }
    // Rows can be expanded out of order.
    std::vector<uint32_t> row2(LWE_N);
    ExpandA(seed, 2, 1, row2.data());
    BOOST_CHECK(std::equal(row2.begin(), row2.end(), rows.begin() + 2 * LWE_N));
    // A different seed gives a different matrix.
    std::vector<uint32_t> other(LWE_N);
    ExpandA(uint256::ONE, 0, 1, other.data());
    BOOST_CHECK(!std::equal(other.begin(), other.end(), rows.begin()));
}

BOOST_AUTO_TEST_CASE(error_cdt)
{
    // The exact table agrees with a double-precision evaluation where double
    // resolves it (relative error about 2^-53, i.e. 2^11 of 2^64), rises
    // strictly until the tail mass drops below 2^-64, then saturates.
    const auto& cdt{ErrorCdt()};
    double weight[ERROR_TAIL + 1], total{0};
    for (int32_t m = 0; m <= ERROR_TAIL; ++m) {
        weight[m] = std::exp(-double(m) * m / (2 * SIGMA * SIGMA)) * (m == 0 ? 1 : 2);
        total += weight[m];
    }
    double cumulative{0};
    for (int32_t m = 0; m < ERROR_TAIL; ++m) {
        cumulative += weight[m];
        const double approx{std::ldexp(cumulative / total, 64)};
        if (m < 40) BOOST_CHECK(std::abs(approx - double(cdt[m])) < 65536.0);
        if (m > 0) BOOST_CHECK(m <= 58 ? cdt[m] > cdt[m - 1] : cdt[m] == cdt[m - 1]);
    }
    BOOST_CHECK_EQUAL(cdt[58], ~uint64_t{0});
    BOOST_CHECK(cdt[57] < ~uint64_t{0});
    // Variance of the tabulated distribution: P(|e| = m) from consecutive thresholds.
    long double var{0};
    for (int32_t m = 1; m <= ERROR_TAIL; ++m) {
        const uint64_t hi{m < ERROR_TAIL ? cdt[m] : ~uint64_t{0}};
        var += (long double)(hi - cdt[m - 1]) * m * m;
    }
    var = std::ldexp(var, -64);
    BOOST_CHECK(std::abs(double(var) - SIGMA * SIGMA) < 1e-6);
}

BOOST_AUTO_TEST_CASE(error_distribution)
{
    const auto rng{MakeSecretRngForTesting(uint256::ONE)};
    constexpr int N{200000};
    double sum{0}, sumsq{0};
    int32_t max_abs{0};
    for (int i = 0; i < N; ++i) {
        const int32_t e{SampleError(*rng)};
        sum += e;
        sumsq += double(e) * e;
        max_abs = std::max(max_abs, std::abs(e));
    }
    const double mean{sum / N};
    const double sd{std::sqrt(sumsq / N - mean * mean)};
    BOOST_CHECK(std::abs(mean) < 0.1);
    BOOST_CHECK(std::abs(sd - SIGMA) < 0.1);
    BOOST_CHECK(max_abs > 20);
}

BOOST_AUTO_TEST_CASE(secret_rng)
{
    // The test generator reproduces FastRandomContext(seed).
    FastRandomContext ref{uint256::ONE};
    const auto det{MakeSecretRngForTesting(uint256::ONE)};
    BOOST_CHECK_EQUAL(det->rand64(), ref.rand64());
    BOOST_CHECK_EQUAL(det->rand32(), ref.rand32());
    // Two strong generators give different secrets for the same query.
    const pir::Params params{4, 3, 1};
    QueryState a, b;
    BOOST_REQUIRE(MakeQuery(params, uint256::ONE, 1, *MakeSecretRng(), a));
    BOOST_REQUIRE(MakeQuery(params, uint256::ONE, 1, *MakeSecretRng(), b));
    BOOST_CHECK(a.secret != b.secret);
}

BOOST_AUTO_TEST_CASE(fetch_random_databases)
{
    FastRandomContext rng{uint256::ONE};
    for (uint32_t k : {1U, 3U}) {
        for (uint32_t n : {1U, 2U, 5U, 64U, 301U}) {
            const uint32_t record_bytes{1 + uint32_t(rng.randrange(40))};
            const Database db{RandomDatabase(rng, record_bytes, n, k)};
            const uint256 seed{rng.rand256()};
            const Hint hint{ComputeHint(db, seed)};
            // First, last and a few random records.
            CheckFetch(db, hint, seed, 0, rng);
            CheckFetch(db, hint, seed, n - 1, rng);
            for (int i = 0; i < 4; ++i) CheckFetch(db, hint, seed, uint32_t(rng.randrange(n)), rng);
        }
    }
}

BOOST_AUTO_TEST_CASE(fetch_full_size_records)
{
    FastRandomContext rng{uint256::ONE};
    const Database db{RandomDatabase(rng, node::PIR_RECORD_BYTES, 1500, 1)};
    const uint256 seed{rng.rand256()};
    const Hint hint{ComputeHint(db, seed)};
    for (int i = 0; i < 4; ++i) CheckFetch(db, hint, seed, uint32_t(rng.randrange(1500)), rng);
}

BOOST_AUTO_TEST_CASE(fetch_extreme_entries)
{
    // Entries of the largest centred magnitude (bytes 0x80 and 0x7f: -128 and
    // 127) maximise the noise. The error of an answer entry is the sum over
    // all columns of entry times error, with standard deviation up to
    // SIGMA * 128 * sqrt(cols): at MAX_COLS columns 1/14 of Delta / 2, the
    // bound in simplepir.h. Fetch at MAX_COLS with one and two records per
    // column, and measure the error of every answer row against that
    // standard deviation, so that noise even twice what the analysis says
    // fails. Signs are random per entry so that rows are independent samples.
    FastRandomContext rng{uint256::ONE};
    double sum_sq_error{0}, sum_var{0};
    uint32_t samples{0};
    for (uint32_t k : {1U, 2U}) {
        const uint32_t record_bytes{16 / k}; // sixteen hint rows either way
        const uint32_t n{MAX_COLS * k};
        Database db{record_bytes, k};
        db.Reserve(n);
        std::vector<uint8_t> rec(record_bytes);
        for (uint32_t i = 0; i < n; ++i) {
            for (auto& byte : rec) byte = rng.randbool() ? 0x80 : 0x7f;
            db.Append(rec);
        }
        BOOST_REQUIRE_EQUAL(db.GetParams().Cols(), MAX_COLS);
        const uint256 seed{rng.rand256()};
        const Hint hint{ComputeHint(db, seed)};

        // One fetch per shape: expanding A for a query at MAX_COLS takes seconds.
        const uint32_t index{uint32_t(rng.randrange(n))};
        QueryState state;
        const auto query{MakeQuery(db.GetParams(), seed, index, *MakeSecretRngForTesting(rng.rand256()), state)};
        BOOST_REQUIRE(query);
        const auto answer{Answer(db, *query, n)};
        BOOST_REQUIRE(answer);
        const auto record{Decode(state, hint, *answer)};
        BOOST_REQUIRE(record);
        const auto expected{db.Record(index)};
        BOOST_CHECK(std::equal(record->begin(), record->end(), expected.begin(), expected.end()));

        // The error of every answer row: row (t, b) holds byte b of slot t of
        // the queried column, so answer - H * s - Delta * entry is its error.
        const uint32_t col{index / k};
        for (uint32_t t = 0; t < k; ++t) {
            for (uint32_t b = 0; b < record_bytes; ++b) {
                const size_t row{size_t{t} * record_bytes + b};
                // Mod 2^32 in 64-bit arithmetic that does not wrap (the
                // integer sanitizer allows wrap-around only in simplepir.cpp).
                uint64_t hs{0};
                for (uint32_t x = 0; x < LWE_N; ++x) hs = (hs + uint64_t{hint[row * LWE_N + x]} * state.secret[x]) & 0xffffffff;
                const int64_t entry{static_cast<int8_t>(db.Record(col * k + t)[b])};
                int64_t centred{(int64_t{(*answer)[row]} - int64_t(hs) - int64_t{DELTA} * entry) % (int64_t{1} << 32)};
                if (centred >= int64_t{1} << 31) centred -= int64_t{1} << 32;
                if (centred < -(int64_t{1} << 31)) centred += int64_t{1} << 32;
                const double error{double(centred)};
                BOOST_CHECK(std::abs(error) < 6 * ErrorStdDevOverHalfDelta(MAX_COLS) * (DELTA / 2.0));
                double sum_sq_entries{0};
                for (uint32_t j = 0; j < MAX_COLS; ++j) {
                    const double d{double(static_cast<int8_t>(db.Record(j * k + t)[b]))};
                    sum_sq_entries += d * d;
                }
                sum_sq_error += error * error;
                sum_var += SIGMA * SIGMA * sum_sq_entries;
                ++samples;
            }
        }
    }
    // The mean squared error over the rows against its expectation: a ratio
    // of 1 within the sampling spread of 32 rows (about 0.25).
    const double ratio{sum_sq_error / sum_var};
    BOOST_TEST_MESSAGE("noise variance / expected over " << samples << " rows: " << ratio);
    BOOST_CHECK(ratio > 0.5 && ratio < 2.0);
}

BOOST_AUTO_TEST_CASE(incremental_hint)
{
    FastRandomContext rng{uint256::ONE};
    for (uint32_t k : {1U, 2U}) {
        Database db{RandomDatabase(rng, 21, 37, k)};
        const uint256 seed{rng.rand256()};
        Hint hint{ComputeHint(db, seed)};
        const Database more{RandomDatabase(rng, 21, 20, k)};
        for (uint32_t i = 0; i < 20; ++i) db.Append(more.Record(i));
        ExtendHint(hint, db, seed, 37);
        BOOST_CHECK(hint == ComputeHint(db, seed));
        CheckFetch(db, hint, seed, 50, rng);
    }
}

BOOST_AUTO_TEST_CASE(prefix_answers)
{
    // A client holding the hint of an older (shorter) version of a database
    // can still query the grown database.
    FastRandomContext rng{uint256::ONE};
    const uint256 seed{rng.rand256()};
    Database db{RandomDatabase(rng, 13, 80, 1)};
    Database old{db};
    old.Truncate(50);
    const Hint old_hint{ComputeHint(old, seed)};
    CheckFetch(db, old_hint, seed, 49, rng, 50);
    CheckFetch(db, old_hint, seed, 3, rng, 50);

    // With several records per column only whole-column prefixes work.
    Database db3{RandomDatabase(rng, 13, 80, 4)};
    Database old3{db3};
    old3.Truncate(48);
    CheckFetch(db3, ComputeHint(old3, seed), seed, 47, rng, 48);
    const auto qrng{MakeSecretRngForTesting(rng.rand256())};
    QueryState state;
    auto query{MakeQuery(pir::Params{13, 50, 4}, seed, 0, *qrng, state)};
    BOOST_REQUIRE(query);
    BOOST_CHECK(!Answer(db3, *query, 50));
    // More records than the database holds.
    auto query2{MakeQuery(pir::Params{13, 81, 1}, seed, 0, *qrng, state)};
    BOOST_REQUIRE(query2);
    BOOST_CHECK(!Answer(db, *query2, 81));
}

BOOST_AUTO_TEST_CASE(malformed_inputs)
{
    FastRandomContext rng{uint256::ONE};
    const Database db{RandomDatabase(rng, 8, 10, 1)};
    const uint256 seed{rng.rand256()};
    const Hint hint{ComputeHint(db, seed)};
    const auto qrng{MakeSecretRngForTesting(rng.rand256())};
    QueryState state;
    BOOST_CHECK(!MakeQuery(db.GetParams(), seed, 10, *qrng, state));
    BOOST_CHECK(!MakeQuery(pir::Params{0, 10, 1}, seed, 0, *qrng, state));
    auto query{MakeQuery(db.GetParams(), seed, 4, *qrng, state)};
    BOOST_REQUIRE(query);

    auto shorter{*query};
    shorter.pop_back();
    BOOST_CHECK(!Answer(db, shorter, 10));
    auto longer{*query};
    longer.push_back(0);
    BOOST_CHECK(!Answer(db, longer, 10));

    auto answer{Answer(db, *query, 10)};
    BOOST_REQUIRE(answer);
    auto short_answer{*answer};
    short_answer.pop_back();
    BOOST_CHECK(!Decode(state, hint, short_answer));
    const Hint short_hint(hint.begin(), hint.end() - 1);
    BOOST_CHECK(!Decode(state, short_hint, *answer));
    QueryState no_secret{state};
    no_secret.secret.clear();
    BOOST_CHECK(!Decode(no_secret, hint, *answer));
    BOOST_CHECK(Decode(state, hint, *answer));
}

BOOST_AUTO_TEST_CASE(output_records)
{
    // A BLSCT output with a range proof fits a record and round-trips.
    const auto out{blsct::CreateOutput(RandomDestination(), 5 * COIN, "memo").out};
    DataStream ss;
    ss << out;
    BOOST_TEST_MESSAGE("BLSCT output serialized size: " << ss.size());
    BOOST_CHECK(ss.size() <= node::PIR_RECORD_BYTES - node::PIR_RECORD_HEADER);
    const auto record{node::EncodeOutputRecord(out)};
    BOOST_CHECK_EQUAL(record.size(), node::PIR_RECORD_BYTES);
    BOOST_CHECK_EQUAL(record[0], node::PIR_RECORD_OUTPUT);
    const auto decoded{node::DecodeOutputRecord(record)};
    BOOST_REQUIRE(decoded);
    BOOST_CHECK(decoded->GetHash() == out.GetHash());

    // Staking outputs carry a second range proof in their script.
    const auto staked{blsct::CreateOutput(RandomDestination(), 5 * COIN, "", TokenId(), BlstScalar::Rand(), blsct::STAKED_COMMITMENT, 1 * COIN).out};
    DataStream staked_ss;
    staked_ss << staked;
    BOOST_TEST_MESSAGE("BLSCT staked commitment output serialized size: " << staked_ss.size());
    BOOST_CHECK_EQUAL(node::EncodeOutputRecord(staked)[0],
                      staked_ss.size() <= node::PIR_RECORD_BYTES - node::PIR_RECORD_HEADER ? node::PIR_RECORD_OUTPUT : node::PIR_RECORD_OVERSIZED);

    // An output too large for a record is marked as such.
    CTxOut big{out};
    const std::vector<unsigned char> long_script(node::PIR_RECORD_BYTES, 0x51);
    big.scriptPubKey = CScript(long_script.begin(), long_script.end());
    const auto big_record{node::EncodeOutputRecord(big)};
    BOOST_CHECK_EQUAL(big_record.size(), node::PIR_RECORD_BYTES);
    BOOST_CHECK_EQUAL(big_record[0], node::PIR_RECORD_OVERSIZED);
    BOOST_CHECK(!node::DecodeOutputRecord(big_record));

    // Corrupt records do not decode.
    auto bad{record};
    bad[1] = 0xff;
    bad[2] = 0xff;
    BOOST_CHECK(!node::DecodeOutputRecord(bad));
    auto truncated{record};
    truncated[1] = uint8_t(truncated[1] - 1);
    BOOST_CHECK(!node::DecodeOutputRecord(truncated));
    BOOST_CHECK(!node::DecodeOutputRecord(Span<const uint8_t>{record}.first(2)));
}

BOOST_AUTO_TEST_CASE(messages_and_client)
{
    FastRandomContext rng{uint256::ONE};
    const uint256 genesis{rng.rand256()};
    const uint32_t epoch{3};
    const Database db{RandomDatabase(rng, node::PIR_RECORD_BYTES, 9, 1)};
    const uint256 seed{node::PirEpochSeed(genesis, epoch)};
    const Hint hint{ComputeHint(db, seed)};

    node::PirHintMsg msg;
    msg.epoch = epoch;
    msg.epoch_blocks = 5;
    msg.start_height = 15;
    msg.anchor_hash = rng.rand256();
    msg.block_counts = {2, 0, 4, 3};
    msg.seed = seed;
    msg.record_bytes = node::PIR_RECORD_BYTES;
    msg.num_records = 9;
    msg.records_per_col = 1;
    msg.slot = 0;
    msg.hint = hint;

    // Serialization round trip.
    DataStream ss;
    ss << msg;
    node::PirHintMsg msg2;
    ss >> msg2;
    BOOST_CHECK(msg2.hint == msg.hint);
    BOOST_CHECK(msg2.block_counts == msg.block_counts);
    BOOST_CHECK(msg2.seed == msg.seed);
    BOOST_CHECK_EQUAL(msg2.status, node::PIR_STATUS_OK);

    // A vector claiming more words than the stream holds fails cleanly.
    DataStream bad;
    bad << uint32_t{0} << uint256{} << uint32_t{0};
    WriteCompactSize(bad, uint64_t{1} << 40);
    bad << uint32_t{7};
    node::PirQueryMsg bad_query;
    BOOST_CHECK_THROW(bad >> bad_query, std::ios_base::failure);

    // The client rejects a hint whose seed is not the chain-derived one, or
    // whose counts do not add up.
    {
        node::PirEpochClient client{genesis};
        auto wrong_seed{msg};
        wrong_seed.seed = rng.rand256();
        BOOST_CHECK(!client.AddHint(wrong_seed));
        auto wrong_counts{msg};
        wrong_counts.block_counts = {2, 0, 4, 4};
        BOOST_CHECK(!client.AddHint(wrong_counts));
        auto wrong_start{msg};
        wrong_start.start_height = 16;
        BOOST_CHECK(!client.AddHint(wrong_start));
        auto short_hint{msg};
        short_hint.hint.pop_back();
        BOOST_CHECK(!client.AddHint(short_hint));
        BOOST_CHECK(!client.Complete());
    }

    node::PirEpochClient client{genesis};
    BOOST_REQUIRE(client.AddHint(msg));
    BOOST_CHECK(client.Complete());
    BOOST_CHECK(!client.IndexOf(14, 0));
    BOOST_CHECK(!client.IndexOf(16, 0)); // no outputs in that block
    BOOST_CHECK_EQUAL(*client.IndexOf(15, 1), 1U);
    BOOST_CHECK_EQUAL(*client.IndexOf(17, 3), 5U);
    BOOST_CHECK_EQUAL(*client.IndexOf(18, 2), 8U);
    BOOST_CHECK(!client.IndexOf(18, 3));
    BOOST_CHECK(!client.IndexOf(19, 0));

    const uint32_t index{*client.IndexOf(17, 3)};
    QueryState state;
    auto query{client.MakeQuery(index, *MakeSecretRngForTesting(rng.rand256()), state)};
    BOOST_REQUIRE(query);
    DataStream qs;
    qs << *query;
    node::PirQueryMsg query2;
    qs >> query2;
    BOOST_CHECK(query2.query == query->query);

    node::PirReplyMsg reply;
    reply.epoch = epoch;
    reply.anchor_hash = msg.anchor_hash;
    reply.answer = *Answer(db, query2.query, query2.num_records);
    auto record{client.Decode(state, reply)};
    BOOST_REQUIRE(record);
    const auto expected{db.Record(index)};
    BOOST_CHECK(std::equal(record->begin(), record->end(), expected.begin(), expected.end()));

    // A reply for another version, or one with a status, does not decode.
    auto other{reply};
    other.anchor_hash = rng.rand256();
    BOOST_CHECK(!client.Decode(state, other));
    for (uint8_t status : {node::PIR_STATUS_STALE, node::PIR_STATUS_BUSY, node::PIR_STATUS_UNAVAILABLE}) {
        auto refused{reply};
        refused.status = status;
        BOOST_CHECK(!client.Decode(state, refused));
        refused.answer.clear();
        BOOST_CHECK(!client.Decode(state, refused));
    }

    // A status-only pirhint round-trips and is rejected, as is a hint with data and a status.
    node::PirHintMsg busy;
    busy.epoch = epoch;
    busy.status = node::PIR_STATUS_BUSY;
    BOOST_CHECK(!node::PirEpochClient{genesis}.AddHint(busy));
    auto busy_with_data{msg};
    busy_with_data.status = node::PIR_STATUS_BUSY;
    BOOST_CHECK(!node::PirEpochClient{genesis}.AddHint(busy_with_data));
    DataStream busy_ss;
    busy_ss << busy;
    node::PirHintMsg busy2;
    busy_ss >> busy2;
    BOOST_CHECK_EQUAL(busy2.status, node::PIR_STATUS_BUSY);
    BOOST_CHECK(busy2.hint.empty() && busy2.block_counts.empty());
}

BOOST_AUTO_TEST_CASE(budget)
{
    const NodeClock::time_point t0{NodeClock::time_point{} + 1000s};
    // Starts partly full and fills at the refill rate, up to capacity.
    node::PirBudget b{1000, 100, 250, t0};
    BOOST_CHECK(!b.TryConsume(300, t0));
    BOOST_CHECK(b.TryConsume(250, t0));
    BOOST_CHECK(!b.TryConsume(1, t0));
    BOOST_CHECK(b.TryConsume(200, t0 + 2s));
    BOOST_CHECK(!b.TryConsume(1001, t0 + 100s));
    BOOST_CHECK(b.TryConsume(1000, t0 + 100s));
    // Charges may go into debt, which refills like anything else.
    b.Charge(500, t0 + 100s);
    BOOST_CHECK(b.InDebt(t0 + 104s));
    BOOST_CHECK(!b.InDebt(t0 + 105s));
    // The initial amount is capped at the capacity.
    node::PirBudget full{10, 1, 20, t0};
    BOOST_CHECK(!full.TryConsume(11, t0));
    BOOST_CHECK(full.TryConsume(10, t0));
}

BOOST_FIXTURE_TEST_CASE(server_builds_in_background, TestChain100Setup)
{
    using Status = node::PirServer::Status;
    // Freeze the clock so that budgets do not refill.
    SetMockTime(GetTime<std::chrono::seconds>());
    node::PirServer::Options opts;
    opts.epoch_blocks = 10; // epochs 0 to 10 up to the tip at height 100
    opts.max_epochs = 16;
    opts.peer_budget = 1600; // a new peer holds 200 and a build costs it 100
    node::PirServer server{*m_node.chainman, opts};
    std::vector<node::PirHintMsg> msgs;

    // A request for an epoch that is not built queues a build and is told
    // to retry; it never builds on the calling thread.
    BOOST_CHECK(server.GetHint(1, 1, msgs) == Status::BUSY);
    BOOST_CHECK(msgs.empty());
    server.SyncWithBuilds();
    BOOST_REQUIRE(server.GetHint(1, 1, msgs) == Status::OK);
    BOOST_REQUIRE_EQUAL(msgs.size(), 1U);
    BOOST_CHECK_EQUAL(msgs[0].start_height, 10U);
    BOOST_CHECK_EQUAL(msgs[0].block_counts.size(), 10U);
    BOOST_CHECK_EQUAL(msgs[0].num_records, 0U); // no BLSCT outputs in this chain
    BOOST_CHECK(msgs[0].anchor_hash == WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain()[19]->GetBlockHash()));
    BOOST_CHECK(msgs[0].seed == node::PirEpochSeed(::Params().GenesisBlock().GetHash(), 1));

    // An epoch above the tip is invalid without queuing anything.
    BOOST_CHECK(server.GetHint(1, 11, msgs) == Status::INVALID);

    // Each build a peer queues is charged up front: one more fits what is
    // left of the peer's starting budget, the next does not and is not
    // queued (but the peer is not disconnected for it).
    BOOST_CHECK(server.GetHint(1, 2, msgs) == Status::BUSY);
    BOOST_CHECK(server.GetHint(1, 3, msgs) == Status::BUSY);
    server.SyncWithBuilds();
    BOOST_CHECK(server.GetHint(2, 2, msgs) == Status::OK);
    BOOST_CHECK(server.GetHint(2, 3, msgs) == Status::BUSY);
    server.SyncWithBuilds();
    BOOST_CHECK(server.GetHint(2, 3, msgs) == Status::OK);
    // The bucket refills with time, and a peer that reconnects starts over
    // with the starting budget, not the full burst.
    SetMockTime(GetTime<std::chrono::seconds>() + 1s);
    BOOST_CHECK(server.GetHint(1, 4, msgs) == Status::BUSY);
    server.ForgetPeer(1);
    for (uint32_t epoch : {5U, 6U}) BOOST_CHECK(server.GetHint(1, epoch, msgs) == Status::BUSY);
    BOOST_CHECK(server.GetHint(1, 7, msgs) == Status::BUSY);
    server.SyncWithBuilds();
    for (uint32_t epoch : {4U, 5U, 6U}) BOOST_CHECK(server.GetHint(3, epoch, msgs) == Status::OK);
    BOOST_CHECK(server.GetHint(3, 7, msgs) == Status::BUSY);

    // The last epoch follows the tip: a new block makes it out of date,
    // and the rebuild extends it.
    BOOST_CHECK(server.GetHint(4, 10, msgs) == Status::BUSY);
    server.SyncWithBuilds();
    BOOST_REQUIRE(server.GetHint(4, 10, msgs) == Status::OK);
    BOOST_CHECK_EQUAL(msgs[0].block_counts.size(), 1U);
    mineBlocks(1);
    BOOST_CHECK(server.GetHint(4, 10, msgs) == Status::BUSY);
    server.SyncWithBuilds();
    BOOST_REQUIRE(server.GetHint(4, 10, msgs) == Status::OK);
    BOOST_CHECK_EQUAL(msgs[0].block_counts.size(), 2U);
    BOOST_CHECK(msgs[0].anchor_hash == WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash()));

    // Queries are answered from a built epoch that reaches their anchor,
    // and otherwise queue a build.
    node::PirQueryMsg query;
    query.epoch = 1;
    query.anchor_hash = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain()[15]->GetBlockHash());
    node::PirReplyMsg reply;
    BOOST_CHECK(server.Answer(3, query, reply) == Status::OK);
    BOOST_CHECK_EQUAL(reply.answer.size(), node::PIR_RECORD_BYTES);
    query.epoch = 8;
    query.anchor_hash = WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain()[85]->GetBlockHash());
    BOOST_CHECK(server.Answer(3, query, reply) == Status::BUSY);
    server.SyncWithBuilds();
    BOOST_CHECK(server.Answer(3, query, reply) == Status::OK);
    // An anchor outside the query's epoch is invalid.
    query.epoch = 7;
    BOOST_CHECK(server.Answer(3, query, reply) == Status::INVALID);

    // Destroying the server with a build queued stops the build thread.
    {
        node::PirServer other{*m_node.chainman, opts};
        BOOST_CHECK(other.GetHint(1, 9, msgs) == Status::BUSY);
    }
    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()
