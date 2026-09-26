// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/archive.h>
#include <p2pmsg/fmd.h>

#include <arith_uint256.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

using namespace p2pmsg;

BOOST_FIXTURE_TEST_SUITE(p2pmsg_archive_tests, BasicTestingSetup)

namespace {

EnvelopeArchive::Options MemOpts(size_t max_bytes = 0, int64_t expiry = 0)
{
    EnvelopeArchive::Options o;
    o.memory_only = true;
    o.max_total_bytes = max_bytes;
    o.expiry_seconds = expiry;
    return o;
}

std::vector<uint8_t> FakeEnvelope(uint8_t tag, size_t len = 64)
{
    std::vector<uint8_t> e(len, tag);
    return e;
}

} // namespace

BOOST_AUTO_TEST_CASE(archive_stores_only_flagged_envelopes)
{
    EnvelopeArchive archive{MemOpts()};
    const auto sk = FmdSecretKey::Random();

    // An unflagged envelope can never be retrieved -- storing it would be pure
    // cost, and it is what keeps the archive proportional to the traffic that
    // actually wants retention rather than to the whole bus.
    BOOST_CHECK(!archive.Add(1000, 7, {}, FakeEnvelope(1)).has_value());
    BOOST_CHECK_EQUAL(archive.Count(), 0U);

    // Nor is an empty envelope stored.
    const auto flag = FmdFlag(sk.GetClueKey());
    BOOST_CHECK(!archive.Add(1000, 7, flag, {}).has_value());
    BOOST_CHECK_EQUAL(archive.Count(), 0U);

    const auto id = archive.Add(1000, 7, flag, FakeEnvelope(1));
    BOOST_REQUIRE(id.has_value());
    BOOST_CHECK_EQUAL(*id, 1U);
    BOOST_CHECK_EQUAL(archive.Count(), 1U);
    BOOST_CHECK_EQUAL(archive.NewestId(), 1U);
    BOOST_CHECK_EQUAL(archive.OldestId(), 1U);
    BOOST_CHECK_GT(archive.TotalBytes(), 0U);
}

BOOST_AUTO_TEST_CASE(archive_scan_returns_only_matching_envelopes)
{
    EnvelopeArchive archive{MemOpts()};
    const auto mine = FmdSecretKey::Random();
    const auto theirs = FmdSecretKey::Random();

    // Ten envelopes for someone else, one for us, ten more for someone else.
    for (int i = 0; i < 10; ++i) archive.Add(1000 + i, 7, FmdFlag(theirs.GetClueKey()), FakeEnvelope(0xaa));
    const auto mine_id = archive.Add(1100, 7, FmdFlag(mine.GetClueKey()), FakeEnvelope(0x42));
    BOOST_REQUIRE(mine_id.has_value());
    for (int i = 0; i < 10; ++i) archive.Add(1200 + i, 7, FmdFlag(theirs.GetClueKey()), FakeEnvelope(0xbb));

    // At full precision the decoy rate is 2^-24, so the scan returns exactly
    // ours.
    const auto res = archive.Scan(0, mine.Extract(FMD_GAMMA), 1000, 100, 1 << 20, 0);
    BOOST_CHECK(res.complete);
    BOOST_CHECK_EQUAL(res.scanned, 21U);
    BOOST_REQUIRE_EQUAL(res.matches.size(), 1U);
    BOOST_CHECK_EQUAL(res.matches[0].id, *mine_id);
    BOOST_CHECK_EQUAL(res.matches[0].envelope[0], 0x42);
    BOOST_CHECK_EQUAL(res.next_cursor, 21U);

    // Resuming from next_cursor finds nothing new and stays complete.
    const auto again = archive.Scan(res.next_cursor, mine.Extract(FMD_GAMMA), 1000, 100, 1 << 20, 0);
    BOOST_CHECK(again.complete);
    BOOST_CHECK_EQUAL(again.scanned, 0U);
    BOOST_CHECK(again.matches.empty());
    BOOST_CHECK_EQUAL(again.next_cursor, res.next_cursor);

    // A stranger's key at full precision finds nothing of ours.
    const auto stranger = FmdSecretKey::Random();
    BOOST_CHECK(archive.Scan(0, stranger.Extract(FMD_GAMMA), 1000, 100, 1 << 20, 0).matches.empty());
}

BOOST_AUTO_TEST_CASE(archive_low_precision_returns_decoys)
{
    // The whole point: a low-precision key returns the requester's messages
    // PLUS a fraction of everyone else's, so the serving node cannot tell which
    // is which.
    EnvelopeArchive archive{MemOpts()};
    const auto mine = FmdSecretKey::Random();
    const auto theirs = FmdSecretKey::Random();

    archive.Add(1000, 7, FmdFlag(mine.GetClueKey()), FakeEnvelope(0x42));
    for (int i = 0; i < 400; ++i) archive.Add(1001 + i, 7, FmdFlag(theirs.GetClueKey()), FakeEnvelope(0xaa));

    const auto res = archive.Scan(0, mine.Extract(2), 1000, 1000, 1 << 20, 0);
    // Ours is always there.
    bool found_ours = false;
    for (const auto& m : res.matches) {
        if (m.envelope[0] == 0x42) found_ours = true;
    }
    BOOST_CHECK(found_ours);
    // At 2^-2 roughly a quarter of the 400 decoys come back too. Loose bounds:
    // a flaky failure here would be worse than a weak assertion.
    BOOST_CHECK_GT(res.matches.size(), 40U);
    BOOST_CHECK_LT(res.matches.size(), 200U);
}

BOOST_AUTO_TEST_CASE(archive_scan_respects_caps_without_losing_matches)
{
    EnvelopeArchive archive{MemOpts()};
    const auto mine = FmdSecretKey::Random();
    for (int i = 0; i < 10; ++i) archive.Add(1000 + i, 7, FmdFlag(mine.GetClueKey()), FakeEnvelope(0x42));

    // max_matches binds. The entry that matched but did not fit must NOT be
    // skipped by the returned cursor, or the requester loses it forever.
    const auto first = archive.Scan(0, mine.Extract(FMD_GAMMA), 1000, 4, 1 << 20, 0);
    BOOST_CHECK(!first.complete);
    BOOST_CHECK_EQUAL(first.matches.size(), 4U);
    BOOST_CHECK_EQUAL(first.next_cursor, 4U);

    const auto second = archive.Scan(first.next_cursor, mine.Extract(FMD_GAMMA), 1000, 4, 1 << 20, 0);
    BOOST_CHECK_EQUAL(second.matches.size(), 4U);
    BOOST_CHECK_EQUAL(second.matches[0].id, 5U);

    const auto third = archive.Scan(second.next_cursor, mine.Extract(FMD_GAMMA), 1000, 4, 1 << 20, 0);
    BOOST_CHECK(third.complete);
    BOOST_CHECK_EQUAL(third.matches.size(), 2U);
    BOOST_CHECK_EQUAL(third.matches[0].id, 9U);
    BOOST_CHECK_EQUAL(third.matches[1].id, 10U);

    // max_entries binds: the scan stops early and says so, and the cursor
    // reflects what was actually scanned.
    const auto capped = archive.Scan(0, mine.Extract(FMD_GAMMA), 3, 100, 1 << 20, 0);
    BOOST_CHECK(!capped.complete);
    BOOST_CHECK_EQUAL(capped.scanned, 3U);
    BOOST_CHECK_EQUAL(capped.next_cursor, 3U);

    // max_bytes binds the same way.
    const auto tiny = archive.Scan(0, mine.Extract(FMD_GAMMA), 1000, 100, 100, 0);
    BOOST_CHECK(!tiny.complete);
    BOOST_CHECK_EQUAL(tiny.matches.size(), 1U);
}

BOOST_AUTO_TEST_CASE(archive_not_before_skips_without_testing)
{
    EnvelopeArchive archive{MemOpts()};
    const auto mine = FmdSecretKey::Random();
    for (int i = 0; i < 5; ++i) archive.Add(1000 + i, 7, FmdFlag(mine.GetClueKey()), FakeEnvelope(0x42));

    const auto res = archive.Scan(0, mine.Extract(FMD_GAMMA), 1000, 100, 1 << 20, /*not_before=*/1003);
    BOOST_CHECK(res.complete);
    BOOST_CHECK_EQUAL(res.scanned, 5U);       // still walked
    BOOST_CHECK_EQUAL(res.matches.size(), 2U); // but only two are recent enough
    BOOST_CHECK_EQUAL(res.matches[0].received_at, 1003);
}

BOOST_AUTO_TEST_CASE(archive_prunes_by_age_and_size)
{
    const auto mine = FmdSecretKey::Random();
    {
        // Age cap: entries older than the window are dropped on the next write.
        EnvelopeArchive archive{MemOpts(/*max_bytes=*/0, /*expiry=*/100)};
        archive.Add(1000, 7, FmdFlag(mine.GetClueKey()), FakeEnvelope(0x11));
        archive.Add(1050, 7, FmdFlag(mine.GetClueKey()), FakeEnvelope(0x22));
        BOOST_CHECK_EQUAL(archive.Count(), 2U);
        archive.Add(1200, 7, FmdFlag(mine.GetClueKey()), FakeEnvelope(0x33));
        // 1000 and 1050 are both more than 100s before 1200.
        BOOST_CHECK_EQUAL(archive.Count(), 1U);
        BOOST_CHECK_EQUAL(archive.OldestId(), 3U);
        // Ids never repeat, so a requester's cursor stays meaningful across
        // pruning: it just finds that older ids are gone.
        BOOST_CHECK_EQUAL(archive.NewestId(), 3U);
    }
    {
        // Size cap: oldest-first eviction. Everything here is opaque
        // ciphertext, so there is no priority class to prefer.
        EnvelopeArchive archive{MemOpts(/*max_bytes=*/600, /*expiry=*/0)};
        for (int i = 0; i < 20; ++i) {
            archive.Add(1000 + i, 7, FmdFlag(mine.GetClueKey()), FakeEnvelope(0x44, 128));
        }
        BOOST_CHECK_LE(archive.TotalBytes(), 600U + 256U);
        BOOST_CHECK_LT(archive.Count(), 20U);
        BOOST_CHECK_GT(archive.OldestId(), 1U);
        BOOST_CHECK_EQUAL(archive.NewestId(), 20U);
    }
}

BOOST_AUTO_TEST_CASE(archive_query_stamp_commits_and_costs)
{
    ArchiveRequest req;
    req.cursor = 42;
    req.limit = 100;
    req.precision = 4;
    req.scan_budget = 1000;
    req.challenge = uint256::ONE;
    req.detection_key = std::vector<uint8_t>(4 * FMD_SCALAR_SIZE, 0x7);
    req.not_before = 1234;

    const uint256 h = req.QueryHash();
    // Every query field is committed to, so a peer cannot pay for a cheap scan
    // and then ask for an expensive one.
    ArchiveRequest other = req;
    other.cursor = 43;
    BOOST_CHECK(other.QueryHash() != h);
    other = req;
    other.precision = 8;
    BOOST_CHECK(other.QueryHash() != h);
    other = req;
    other.limit = 500;
    BOOST_CHECK(other.QueryHash() != h);
    other = req;
    other.not_before = 0;
    BOOST_CHECK(other.QueryHash() != h);
    other = req;
    other.detection_key[0] ^= 1;
    BOOST_CHECK(other.QueryHash() != h);
    // The budget is what the stamp is PRICED on, so it has to be committed to
    // or a cheap grind would buy the largest scan there is.
    other = req;
    other.scan_budget = 50000;
    BOOST_CHECK(other.QueryHash() != h);
    // ...and so does the server's challenge, or the same grind is spendable on
    // every connection and at every archive node.
    other = req;
    other.challenge = uint256::ZERO;
    BOOST_CHECK(other.QueryHash() != h);

    req.stamp.timestamp = 1000;
    req.stamp.query_hash = h;
    const uint32_t bits = ArchiveStampBits(4, req.scan_budget, req.precision);
    BOOST_CHECK_GE(bits, 4U);
    BOOST_CHECK(GrindArchiveStamp(req.stamp, bits, 1 << 22) > 0);
    BOOST_CHECK(UintToArith256(req.stamp.Hash()) <= TargetFromBits(bits));

    // Difficulty rises with the work requested and is clamped so a large
    // legitimate query stays feasible. These exact values are mirrored in the
    // TypeScript SDK (src/archive/protocol.test.ts): the two must agree or
    // every query the SDK sends is rejected here as underpowered.
    BOOST_CHECK_EQUAL(ArchiveStampBits(4, 1, 1), 4U);
    BOOST_CHECK_EQUAL(ArchiveStampBits(4, 1000, 4), 4U); // exactly the free allowance
    BOOST_CHECK_EQUAL(ArchiveStampBits(4, 2000, 4), 5U);
    BOOST_CHECK_EQUAL(ArchiveStampBits(4, 1000, 8), 5U);
    BOOST_CHECK_GE(ArchiveStampBits(4, 50000, FMD_GAMMA), ArchiveStampBits(4, 1000, 4));
    BOOST_CHECK_LE(ArchiveStampBits(4, 50000, FMD_GAMMA), 4U + 8U);

    // The case the old curve mispriced: `limit` bounds MATCHES, so a
    // high-precision key that matches nothing returned cheaply while walking
    // the entire window. Pricing the budget makes the expensive query the
    // expensive one.
    BOOST_CHECK_EQUAL(ArchiveStampBits(4, 1, 24), 4U);

    // The per-entry constant is priced, not just the precision product. Every
    // entry costs a decompress and a subgroup check on top of its
    // multiplications, so a low-precision scan is not as cheap as the bare
    // product suggests. Pricing (precision + 2) is what this pins: on the old
    // scan_budget x precision curve this query was 3000 units against a 4000
    // allowance and cost the base; it now costs a bit more.
    BOOST_CHECK_EQUAL(ArchiveStampBits(4, 3000, 1), 5U);
    BOOST_CHECK_GT(ArchiveStampBits(4, MAX_ARCHIVE_SCAN_ENTRIES, 24),
                   ArchiveStampBits(4, 1, 24));
}

// A scan must not run on the message-handling thread: it can walk
// MAX_ARCHIVE_SCAN_ENTRIES flags while holding the archive mutex that the
// decrypt workers need. ArchiveScanner is where that work goes.
BOOST_AUTO_TEST_CASE(archive_scanner_defers_and_bounds_work)
{
    EnvelopeArchive archive{MemOpts()};

    FmdSecretKey mine = FmdSecretKey::Random();
    for (int i = 0; i < 6; ++i) {
        const auto flag = FmdFlag(mine.GetClueKey());
        archive.Add(1000 + i, /*kind=*/1, flag, FakeEnvelope(uint8_t(i)));
    }

    std::vector<std::pair<PeerId, ArchiveResponse>> sent;
    ArchiveScanner scanner{archive, [&sent](PeerId peer, ArchiveResponse&& resp, size_t) {
                               sent.emplace_back(peer, std::move(resp));
                           },
                           /*queue_capacity=*/2};

    const auto key = mine.Extract(FMD_GAMMA);
    const std::vector<uint8_t> key_bytes(key.begin(), key.end());

    // Enqueue returns immediately and nothing has been scanned yet: that is
    // the whole point.
    BOOST_REQUIRE(scanner.Enqueue(7, 0, key_bytes, /*scan_budget=*/1000, /*limit=*/100, 0));
    BOOST_CHECK_EQUAL(scanner.QueueDepth(), 1U);
    BOOST_CHECK(sent.empty());

    // The queue is bounded, and a full one refuses rather than growing.
    BOOST_REQUIRE(scanner.Enqueue(7, 0, key_bytes, 1000, 100, 0));
    BOOST_CHECK(!scanner.Enqueue(7, 0, key_bytes, 1000, 100, 0));

    BOOST_CHECK_EQUAL(scanner.DrainForTest(), 2U);
    BOOST_REQUIRE_EQUAL(sent.size(), 2U);
    BOOST_CHECK_EQUAL(sent[0].first, 7);
    BOOST_CHECK_EQUAL(sent[0].second.items.size(), 6U);

    // The budget bounds the walk, and a scan cut short says so rather than
    // claiming it reached the end.
    sent.clear();
    BOOST_REQUIRE(scanner.Enqueue(9, 0, key_bytes, /*scan_budget=*/2, /*limit=*/100, 0));
    BOOST_CHECK_EQUAL(scanner.DrainForTest(), 1U);
    BOOST_REQUIRE_EQUAL(sent.size(), 1U);
    BOOST_CHECK_EQUAL(sent[0].second.items.size(), 2U);
    BOOST_CHECK_EQUAL(sent[0].second.complete, 0);
}

BOOST_AUTO_TEST_SUITE_END()
