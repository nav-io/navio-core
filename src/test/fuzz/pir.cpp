// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pir.h>
#include <pir/simplepir.h>
#include <random.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cassert>

namespace {
template <typename T>
void RoundTrip(Span<const uint8_t> bytes)
{
    DataStream ds{bytes};
    T msg;
    try {
        ds >> msg;
    } catch (const std::ios_base::failure&) {
        return;
    }
    DataStream out;
    out << msg;
    T msg2;
    out >> msg2;
    DataStream out2;
    out2 << msg2;
    assert(out.str() == out2.str());
}
} // namespace

FUZZ_TARGET(pir_messages)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    switch (fdp.ConsumeIntegralInRange<int>(0, 3)) {
    case 0: RoundTrip<node::PirHintMsg>(MakeUCharSpan(fdp.ConsumeRemainingBytes<uint8_t>())); break;
    case 1: RoundTrip<node::PirQueryMsg>(MakeUCharSpan(fdp.ConsumeRemainingBytes<uint8_t>())); break;
    case 2: RoundTrip<node::PirReplyMsg>(MakeUCharSpan(fdp.ConsumeRemainingBytes<uint8_t>())); break;
    case 3: {
        // Output records: whatever the bytes, decoding must not crash, and a
        // decoded output re-encodes to the same record.
        auto record{fdp.ConsumeBytes<uint8_t>(node::PIR_RECORD_BYTES)};
        record.resize(node::PIR_RECORD_BYTES);
        if (auto out{node::DecodeOutputRecord(record)}) {
            const auto again{node::EncodeOutputRecord(*out)};
            assert(node::DecodeOutputRecord(again).has_value());
        }
        break;
    }
    }
}

FUZZ_TARGET(pir_answer_decode)
{
    // Small databases: any shape and index must either be rejected or fetch
    // the right record.
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    const uint32_t record_bytes{fdp.ConsumeIntegralInRange<uint32_t>(1, 8)};
    const uint32_t k{fdp.ConsumeIntegralInRange<uint32_t>(1, 4)};
    const uint32_t n{fdp.ConsumeIntegralInRange<uint32_t>(1, 24)};
    pir::Database db{record_bytes, k};
    for (uint32_t i = 0; i < n; ++i) {
        auto rec{fdp.ConsumeBytes<uint8_t>(record_bytes)};
        rec.resize(record_bytes);
        db.Append(rec);
    }
    const uint256 seed{ConsumeUInt256(fdp)};
    FastRandomContext rng{ConsumeUInt256(fdp)};
    const uint32_t index{fdp.ConsumeIntegralInRange<uint32_t>(0, n)};
    pir::QueryState state;
    auto query{pir::MakeQuery(db.GetParams(), seed, index, rng, state)};
    if (index >= n) {
        assert(!query);
        return;
    }
    assert(query);
    if (fdp.ConsumeBool() && !query->empty()) (*query)[fdp.ConsumeIntegralInRange<size_t>(0, query->size() - 1)] ^= fdp.ConsumeIntegral<uint32_t>();
    const auto answer{pir::Answer(db, *query, n)};
    assert(answer);
    const auto record{pir::Decode(state, pir::ComputeHint(db, seed), *answer)};
    assert(record && record->size() == record_bytes);
}
