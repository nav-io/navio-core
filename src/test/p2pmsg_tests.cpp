// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/crypto.h>
#include <p2pmsg/pow.h>
#include <p2pmsg/transport.h>
#include <p2pmsg/worker_pool.h>

#include <blsct/private_key.h>
#include <blsct/arith/mcl/mcl_scalar.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

using namespace p2pmsg;

BOOST_FIXTURE_TEST_SUITE(p2pmsg_tests, BasicTestingSetup)

namespace {
//! Make a Job of the given kind with `len` bytes of payload (buf[i] = i).
Job MakeJob(uint8_t kind, uint32_t len = 0)
{
    Job j;
    j.kind = kind;
    j.peer = 7;
    j.len = len;
    for (uint32_t i = 0; i < len && i < MAX_JOB_BYTES; ++i) {
        j.buf[i] = static_cast<uint8_t>(i & 0xff);
    }
    return j;
}
} // namespace

BOOST_AUTO_TEST_CASE(worker_defaults)
{
    BOOST_CHECK_GE(DefaultWorkerCount(), 1u);
    BOOST_CHECK_LE(DefaultWorkerCount(), 2u);
    BOOST_CHECK_GE(DefaultRingCapacity(1), 64u);
    BOOST_CHECK_EQUAL(DefaultRingCapacity(4), 2u * 4u * 64u);
}

BOOST_AUTO_TEST_CASE(executes_all_submitted_jobs)
{
    std::atomic<int> seen{0};
    std::atomic<uint64_t> sum_first_byte{0};

    WorkerPool pool{WorkerPool::Options{/*num_workers=*/4, /*ring_capacity=*/256}};
    pool.RegisterHandler(1, [&](const Job& j) {
        if (j.len > 0) sum_first_byte.fetch_add(j.buf[0], std::memory_order_relaxed);
        seen.fetch_add(1, std::memory_order_relaxed);
    });
    pool.Start();

    constexpr int N = 1000;
    int enqueued = 0;
    for (int i = 0; i < N; ++i) {
        // Vary len so buf[0] differs; spin briefly if ring momentarily full.
        Job j = MakeJob(1, /*len=*/1 + (i % 16));
        while (!pool.Enqueue(j)) {
            std::this_thread::yield();
        }
        ++enqueued;
    }

    // Drain: Stop() joins workers after the ring empties (no stopping race here
    // because we wait for completion first).
    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (seen.load() < enqueued && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }

    BOOST_CHECK_EQUAL(seen.load(), enqueued);
    BOOST_CHECK_EQUAL(pool.Submitted(), static_cast<uint64_t>(enqueued));
    BOOST_CHECK_EQUAL(pool.Completed(), static_cast<uint64_t>(enqueued));
}

BOOST_AUTO_TEST_CASE(drop_on_overflow)
{
    // One worker, tiny ring, handler blocks until released so the ring fills.
    std::mutex m;
    std::condition_variable cv;
    bool release = false;
    std::atomic<int> handled{0};

    WorkerPool pool{WorkerPool::Options{/*num_workers=*/1, /*ring_capacity=*/4}};
    pool.RegisterHandler(2, [&](const Job&) {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [&] { return release; });
        handled.fetch_add(1, std::memory_order_relaxed);
    });
    pool.Start();

    // First job is picked up by the worker and blocks. Subsequent jobs fill the
    // ring of capacity 4; the 6th onward must be dropped.
    int accepted = 0, dropped = 0;
    for (int i = 0; i < 50; ++i) {
        if (pool.Enqueue(MakeJob(2))) ++accepted; else ++dropped;
    }

    BOOST_CHECK_GT(dropped, 0);
    BOOST_CHECK_EQUAL(static_cast<int>(pool.Dropped()), dropped);
    BOOST_CHECK_EQUAL(accepted + dropped, 50);
    // At most (ring capacity) jobs sit in the ring, plus at most one in-flight
    // in the (blocked) worker.
    BOOST_CHECK_LE(accepted, static_cast<int>(pool.RingCapacity()) + 1);

    {
        std::lock_guard<std::mutex> lk(m);
        release = true;
    }
    cv.notify_all();
    pool.Stop();
}

BOOST_AUTO_TEST_CASE(stop_discards_pending_as_dropped)
{
    std::mutex m;
    std::condition_variable cv;
    bool release = false;

    WorkerPool pool{WorkerPool::Options{/*num_workers=*/1, /*ring_capacity=*/16}};
    pool.RegisterHandler(3, [&](const Job&) {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [&] { return release; });
    });
    pool.Start();

    // Worker grabs the first and blocks; the rest sit in the ring.
    int accepted = 0;
    for (int i = 0; i < 10; ++i) {
        if (pool.Enqueue(MakeJob(3))) ++accepted;
    }

    {
        std::lock_guard<std::mutex> lk(m);
        release = true;
    }
    cv.notify_all();
    pool.Stop();

    // Every accepted job is either completed or dropped; none vanish.
    BOOST_CHECK_EQUAL(pool.Completed() + pool.Dropped(), static_cast<uint64_t>(accepted));
}

BOOST_AUTO_TEST_CASE(enqueue_after_stop_fails)
{
    WorkerPool pool{WorkerPool::Options{/*num_workers=*/2, /*ring_capacity=*/8}};
    pool.RegisterHandler(4, [](const Job&) {});
    pool.Start();
    pool.Stop();

    BOOST_CHECK(!pool.Enqueue(MakeJob(4)));
}

BOOST_AUTO_TEST_CASE(unregistered_kind_is_counted_complete)
{
    std::atomic<int> handled{0};
    WorkerPool pool{WorkerPool::Options{/*num_workers=*/2, /*ring_capacity=*/16}};
    pool.RegisterHandler(5, [&](const Job&) { handled.fetch_add(1, std::memory_order_relaxed); });
    pool.Start();

    BOOST_CHECK(pool.Enqueue(MakeJob(5)));   // handled
    BOOST_CHECK(pool.Enqueue(MakeJob(99)));  // no handler, still dequeued

    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (pool.Completed() < 2 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    BOOST_CHECK_EQUAL(pool.Completed(), 2u);
    BOOST_CHECK_EQUAL(handled.load(), 1);
}

// ---- ECIES ----

BOOST_AUTO_TEST_CASE(ecies_roundtrip)
{
    blsct::PrivateKey sk(MclScalar::Rand(true));
    blsct::PublicKey pk = sk.GetPublicKey();

    std::vector<uint8_t> pt{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    EciesPacket pkt = Encrypt(pk, pt);

    auto out = Decrypt(sk, pkt);
    BOOST_REQUIRE(out.has_value());
    BOOST_CHECK(*out == pt);
}

BOOST_AUTO_TEST_CASE(ecies_empty_plaintext)
{
    blsct::PrivateKey sk(MclScalar::Rand(true));
    EciesPacket pkt = Encrypt(sk.GetPublicKey(), {});
    auto out = Decrypt(sk, pkt);
    BOOST_REQUIRE(out.has_value());
    BOOST_CHECK(out->empty());
}

BOOST_AUTO_TEST_CASE(ecies_wrong_key_fails)
{
    blsct::PrivateKey sk(MclScalar::Rand(true));
    blsct::PrivateKey other(MclScalar::Rand(true));
    std::vector<uint8_t> pt{42, 42, 42};
    EciesPacket pkt = Encrypt(sk.GetPublicKey(), pt);

    BOOST_CHECK(!Decrypt(other, pkt).has_value());
}

BOOST_AUTO_TEST_CASE(ecies_tag_flip_rejected)
{
    blsct::PrivateKey sk(MclScalar::Rand(true));
    std::vector<uint8_t> pt{9, 8, 7, 6};
    EciesPacket pkt = Encrypt(sk.GetPublicKey(), pt);
    pkt.tag[0] ^= 0x01;
    BOOST_CHECK(!Decrypt(sk, pkt).has_value());
}

BOOST_AUTO_TEST_CASE(ecies_ciphertext_flip_rejected)
{
    blsct::PrivateKey sk(MclScalar::Rand(true));
    std::vector<uint8_t> pt{5, 5, 5, 5, 5};
    EciesPacket pkt = Encrypt(sk.GetPublicKey(), pt);
    pkt.ciphertext[0] ^= 0x80;
    BOOST_CHECK(!Decrypt(sk, pkt).has_value());
}

// ---- PoW ----

BOOST_AUTO_TEST_CASE(pow_grind_and_check)
{
    PoWHeader h;
    h.version = 1;
    h.timestamp = 1000;
    h.kind = static_cast<uint8_t>(PayloadKind::RFQ_REQ);
    h.payload_hash = uint256::ONE;

    const uint32_t bits = 8; // easy
    BOOST_CHECK(!CheckPoW(h, bits) || h.nonce == 0); // pre-grind likely fails
    uint64_t attempts = Grind(h, bits);
    BOOST_CHECK_GT(attempts, 0u);
    BOOST_CHECK(CheckPoW(h, bits));
}

BOOST_AUTO_TEST_CASE(pow_rejects_low_difficulty)
{
    PoWHeader h;
    h.timestamp = 5000;
    h.payload_hash = uint256::ONE;
    Grind(h, /*bits=*/4);
    // A stamp ground at 4 bits will almost never satisfy 32 bits.
    BOOST_CHECK(!CheckPoW(h, 32));
}

BOOST_AUTO_TEST_CASE(pow_timestamp_window)
{
    PoWHeader h;
    h.timestamp = 10000;
    h.payload_hash = uint256::ONE;
    Grind(h, /*bits=*/8);

    BOOST_CHECK(CheckStamp(h, 8, /*now=*/10000));
    BOOST_CHECK(CheckStamp(h, 8, /*now=*/10000 + POW_TIMESTAMP_TOLERANCE_SECONDS));
    BOOST_CHECK(!CheckStamp(h, 8, /*now=*/10000 + POW_TIMESTAMP_TOLERANCE_SECONDS + 1));
    BOOST_CHECK(!CheckStamp(h, 8, /*now=*/10000 - POW_TIMESTAMP_TOLERANCE_SECONDS - 1));
}

// ---- Transport end-to-end (loopback) ----

namespace {
//! A loopback harness: broadcast feeds straight back into OnWire so a node can
//! message itself through the full encode/PoW/enqueue/decrypt/dispatch path.
struct LoopbackTransport {
    WorkerPool pool;
    std::unique_ptr<Transport> t;

    explicit LoopbackTransport(uint32_t bits)
        : pool(WorkerPool::Options{/*num_workers=*/2, /*ring_capacity=*/64})
    {
        Transport::Options opts;
        opts.pow_bits = bits;
        t = std::make_unique<Transport>(
            pool,
            /*send=*/[](int64_t, bool, const Envelope&) {},
            /*broadcast=*/[this](bool stem, const Envelope& env) {
                // Serialize, then feed back in as if received from peer 1.
                DataStream ss;
                ss << env;
                auto bytes = MakeUCharSpan(ss);
                std::vector<uint8_t> v(bytes.begin(), bytes.end());
                t->OnWire(/*from_peer=*/1, stem, v);
            },
            /*relay=*/[](int64_t, bool, const Envelope&) {},
            opts);
        pool.Start();
    }
    ~LoopbackTransport() { pool.Stop(); }
};
} // namespace

BOOST_AUTO_TEST_CASE(transport_ping_loopback)
{
    LoopbackTransport h(/*bits=*/4);

    std::atomic<int> pings{0};
    std::vector<uint8_t> got;
    std::mutex gm;
    h.t->RegisterHandler(PayloadKind::PING, [&](const InboundMessage& m) {
        {
            std::lock_guard<std::mutex> lk(gm);
            got = m.body;
        }
        pings.fetch_add(1, std::memory_order_relaxed);
    });

    std::vector<uint8_t> payload{0xde, 0xad, 0xbe, 0xef};
    // Send to our own inbox key (non-PoW kind), broadcast loops it back in.
    h.t->Send(h.t->InboxPubKey(), PayloadKind::PING, payload, /*stem=*/false);

    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (pings.load() < 1 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    BOOST_CHECK_EQUAL(pings.load(), 1);
    std::lock_guard<std::mutex> lk(gm);
    BOOST_CHECK(got == payload);
}

BOOST_AUTO_TEST_CASE(transport_pow_kind_loopback)
{
    LoopbackTransport h(/*bits=*/6);

    std::atomic<int> reqs{0};
    h.t->RegisterHandler(PayloadKind::RFQ_REQ, [&](const InboundMessage&) {
        reqs.fetch_add(1, std::memory_order_relaxed);
    });

    h.t->Send(h.t->InboxPubKey(), PayloadKind::RFQ_REQ, {1, 2, 3}, /*stem=*/true);

    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 10s;
    while (reqs.load() < 1 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    BOOST_CHECK_EQUAL(reqs.load(), 1);
}

namespace {
//! Build a properly PoW-stamped envelope (every message carries one now).
Envelope StampedEnvelope(const blsct::PublicKey& inbox, PayloadKind kind,
                         std::vector<uint8_t> payload, uint32_t bits, int64_t now)
{
    Envelope env;
    env.kind = static_cast<uint8_t>(kind);
    env.enc = Encrypt(inbox, payload);
    env.pow.version = 1;
    env.pow.timestamp = now;
    env.pow.kind = env.kind;
    env.pow.session_eph = env.enc.eph;
    env.pow.payload_hash = env.enc.MsgHash();
    Grind(env.pow, bits);
    return env;
}

std::vector<uint8_t> SerEnv(const Envelope& env)
{
    DataStream ss;
    ss << env;
    auto bytes = MakeUCharSpan(ss);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}
} // namespace

BOOST_AUTO_TEST_CASE(transport_replay_rejected)
{
    LoopbackTransport h(/*bits=*/4);
    h.t->now_override = 1000;
    h.t->RegisterHandler(PayloadKind::PING, [&](const InboundMessage&) {});

    auto env = StampedEnvelope(h.t->InboxPubKey(), PayloadKind::PING, {7, 7}, /*bits=*/4, /*now=*/1000);
    auto v = SerEnv(env);

    auto r1 = h.t->OnWire(1, false, v);
    auto r2 = h.t->OnWire(1, false, v);
    BOOST_CHECK(r1 == Transport::WireResult::Enqueued);
    BOOST_CHECK(r2 == Transport::WireResult::RejectReplay);
}

BOOST_AUTO_TEST_CASE(transport_bad_pow_rejected)
{
    LoopbackTransport h(/*bits=*/16);

    // An envelope with an unsolved PoW (nonce 0, far below 16-bit difficulty)
    // is rejected at the mandatory gate.
    Envelope env;
    env.kind = static_cast<uint8_t>(PayloadKind::RFQ_REQ);
    env.enc = Encrypt(h.t->InboxPubKey(), std::vector<uint8_t>{1});
    env.pow.kind = env.kind;
    env.pow.timestamp = h.t->now_override ? h.t->now_override : 1;
    env.pow.session_eph = env.enc.eph;
    env.pow.payload_hash = env.enc.MsgHash();
    env.pow.nonce = 0; // not ground

    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(env)) == Transport::WireResult::RejectPoW);
}

BOOST_AUTO_TEST_CASE(transport_relays_to_other_peers)
{
    // A node relays a new valid message to peers other than its origin, even for
    // a kind it has no handler for (app-agnostic bus).
    WorkerPool pool{WorkerPool::Options{/*num_workers=*/1, /*ring_capacity=*/16}};
    std::atomic<int> relayed{0};
    std::atomic<int64_t> relay_origin{-1};
    Transport::Options opts; opts.pow_bits = 4;
    Transport t(
        pool,
        [](int64_t, bool, const Envelope&) {},
        [](bool, const Envelope&) {},
        [&](int64_t origin, bool, const Envelope&) { relay_origin = origin; relayed.fetch_add(1); },
        opts);
    t.now_override = 1000;
    pool.Start();

    // An unknown kind (99) addressed to nobody we can decrypt — still relayed.
    auto env = StampedEnvelope(t.InboxPubKey(), static_cast<PayloadKind>(99), {1, 2, 3}, 4, t.now_override);
    auto res = t.OnWire(/*from_peer=*/42, false, SerEnv(env));
    BOOST_CHECK(res == Transport::WireResult::Enqueued);
    BOOST_CHECK_EQUAL(relayed.load(), 1);
    BOOST_CHECK_EQUAL(relay_origin.load(), 42);

    // Replay of the same message is not relayed again (loop breaker).
    t.OnWire(/*from_peer=*/7, false, SerEnv(env));
    BOOST_CHECK_EQUAL(relayed.load(), 1);
    pool.Stop();
}

BOOST_AUTO_TEST_SUITE_END()
