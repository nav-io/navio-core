// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/double_public_key.h>
#include <blsct/wallet/txfactory_global.h>
#include <crypto/common.h>
#include <node/pir.h>
#include <pir/simplepir.h>
#include <random.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

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
    auto query{MakeQuery(params, seed, index, rng, state)};
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

BOOST_AUTO_TEST_CASE(error_distribution)
{
    FastRandomContext rng{uint256::ONE};
    constexpr int N{200000};
    double sum{0}, sumsq{0};
    int32_t max_abs{0};
    for (int i = 0; i < N; ++i) {
        const int32_t e{SampleError(rng)};
        sum += e;
        sumsq += double(e) * e;
        max_abs = std::max(max_abs, std::abs(e));
    }
    const double mean{sum / N};
    const double sd{std::sqrt(sumsq / N - mean * mean)};
    BOOST_CHECK(std::abs(mean) < 0.1);
    BOOST_CHECK(std::abs(sd - SIGMA) < 0.1);
    BOOST_CHECK(max_abs <= 64);
    BOOST_CHECK(max_abs > 20);
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
    // Every entry at the largest centred magnitude (-128) maximises the noise.
    FastRandomContext rng{uint256::ONE};
    Database db{16, 1};
    const std::vector<uint8_t> rec(16, 0x80);
    for (int i = 0; i < 4096; ++i) db.Append(rec);
    std::vector<uint8_t> marked(16, 0x7f);
    db.Append(marked);
    const uint256 seed{rng.rand256()};
    const Hint hint{ComputeHint(db, seed)};
    CheckFetch(db, hint, seed, 4096, rng);
    CheckFetch(db, hint, seed, 17, rng);
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
    QueryState state;
    auto query{MakeQuery(pir::Params{13, 50, 4}, seed, 0, rng, state)};
    BOOST_REQUIRE(query);
    BOOST_CHECK(!Answer(db3, *query, 50));
    // More records than the database holds.
    auto query2{MakeQuery(pir::Params{13, 81, 1}, seed, 0, rng, state)};
    BOOST_REQUIRE(query2);
    BOOST_CHECK(!Answer(db, *query2, 81));
}

BOOST_AUTO_TEST_CASE(malformed_inputs)
{
    FastRandomContext rng{uint256::ONE};
    const Database db{RandomDatabase(rng, 8, 10, 1)};
    const uint256 seed{rng.rand256()};
    const Hint hint{ComputeHint(db, seed)};
    QueryState state;
    BOOST_CHECK(!MakeQuery(db.GetParams(), seed, 10, rng, state));
    BOOST_CHECK(!MakeQuery(pir::Params{0, 10, 1}, seed, 0, rng, state));
    auto query{MakeQuery(db.GetParams(), seed, 4, rng, state)};
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
    auto query{client.MakeQuery(index, rng, state)};
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

    // A reply for another version, or the empty (stale) reply, does not decode.
    auto other{reply};
    other.anchor_hash = rng.rand256();
    BOOST_CHECK(!client.Decode(state, other));
    auto stale{reply};
    stale.answer.clear();
    BOOST_CHECK(!client.Decode(state, stale));
}

BOOST_AUTO_TEST_SUITE_END()
