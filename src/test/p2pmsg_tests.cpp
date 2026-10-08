// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/crypto.h>
#include <p2pmsg/fmd.h>
#include <p2pmsg/pow.h>
#include <p2pmsg/transport.h>
#include <p2pmsg/worker_pool.h>
#include <p2pmsg/user_data.h>
#include <p2pmsg/user_inbox.h>

#include <blsct/private_key.h>
#include <blsct/arith/blst/blst_scalar.h>
#include <test/util/setup_common.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <numeric>
#include <string>
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

//! Spin until `pred` holds, up to a generous ceiling. Returns false on timeout,
//! so a genuine hang fails the test rather than hanging the suite. The ceiling
//! is only reached when something is actually broken, so it can be generous
//! without slowing a passing run down.
template <typename Pred>
bool WaitFor(Pred pred, std::chrono::milliseconds timeout = std::chrono::seconds{30})
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!pred()) {
        if (std::chrono::steady_clock::now() > deadline) return false;
        std::this_thread::yield();
    }
    return true;
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
    blsct::PrivateKey sk(BlstScalar::Rand(true));
    blsct::PublicKey pk = sk.GetPublicKey();

    std::vector<uint8_t> pt{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    EciesPacket pkt = Encrypt(pk, pt);

    auto out = Decrypt(sk, pkt);
    BOOST_REQUIRE(out.has_value());
    BOOST_CHECK(*out == pt);
}

BOOST_AUTO_TEST_CASE(ecies_empty_plaintext)
{
    blsct::PrivateKey sk(BlstScalar::Rand(true));
    EciesPacket pkt = Encrypt(sk.GetPublicKey(), {});
    auto out = Decrypt(sk, pkt);
    BOOST_REQUIRE(out.has_value());
    BOOST_CHECK(out->empty());
}

BOOST_AUTO_TEST_CASE(ecies_aad_mismatch_rejected)
{
    // The kind byte is carried as AEAD associated data. A ciphertext encrypted
    // under one kind must not authenticate under a different kind: this is what
    // stops an attacker flipping the cleartext kind to route the same ciphertext
    // to a different handler.
    blsct::PrivateKey sk(BlstScalar::Rand(true));
    const std::vector<uint8_t> pt{9, 8, 7};
    const uint8_t kindA[1] = {3};
    const uint8_t kindB[1] = {4};
    EciesPacket pkt = Encrypt(sk.GetPublicKey(), pt, std::span<const uint8_t>{kindA, 1});
    BOOST_CHECK(Decrypt(sk, pkt, std::span<const uint8_t>{kindA, 1}).has_value());
    BOOST_CHECK(!Decrypt(sk, pkt, std::span<const uint8_t>{kindB, 1}).has_value());
}

BOOST_AUTO_TEST_CASE(ecies_padding_hides_length)
{
    // Two payloads of different lengths that fall in the same padding bucket
    // must produce ciphertexts of identical length, so the wire size does not
    // reveal the exact application payload size.
    blsct::PrivateKey sk(BlstScalar::Rand(true));
    EciesPacket a = Encrypt(sk.GetPublicKey(), std::vector<uint8_t>(5, 0xaa));
    EciesPacket b = Encrypt(sk.GetPublicKey(), std::vector<uint8_t>(40, 0xbb));
    BOOST_CHECK_EQUAL(a.ciphertext.size(), b.ciphertext.size());
    // And each still round-trips to its exact original length.
    auto ra = Decrypt(sk, a);
    auto rb = Decrypt(sk, b);
    BOOST_REQUIRE(ra && rb);
    BOOST_CHECK_EQUAL(ra->size(), 5u);
    BOOST_CHECK_EQUAL(rb->size(), 40u);
}

BOOST_AUTO_TEST_CASE(ecies_wrong_key_fails)
{
    blsct::PrivateKey sk(BlstScalar::Rand(true));
    blsct::PrivateKey other(BlstScalar::Rand(true));
    std::vector<uint8_t> pt{42, 42, 42};
    EciesPacket pkt = Encrypt(sk.GetPublicKey(), pt);

    BOOST_CHECK(!Decrypt(other, pkt).has_value());
}

BOOST_AUTO_TEST_CASE(ecies_tag_flip_rejected)
{
    blsct::PrivateKey sk(BlstScalar::Rand(true));
    std::vector<uint8_t> pt{9, 8, 7, 6};
    EciesPacket pkt = Encrypt(sk.GetPublicKey(), pt);
    pkt.tag[0] ^= 0x01;
    BOOST_CHECK(!Decrypt(sk, pkt).has_value());
}

BOOST_AUTO_TEST_CASE(ecies_ciphertext_flip_rejected)
{
    blsct::PrivateKey sk(BlstScalar::Rand(true));
    std::vector<uint8_t> pt{5, 5, 5, 5, 5};
    EciesPacket pkt = Encrypt(sk.GetPublicKey(), pt);
    pkt.ciphertext[0] ^= 0x80;
    BOOST_CHECK(!Decrypt(sk, pkt).has_value());
}

BOOST_AUTO_TEST_CASE(ecies_broadcast_key_roundtrip)
{
    // A public announcement encrypted to the well-known broadcast key is
    // readable by anyone holding the (constant) broadcast private key.
    std::vector<uint8_t> pt{0xAA, 0xBB, 0xCC};
    EciesPacket pkt = Encrypt(BroadcastPubKey(), pt);
    auto out = Decrypt(BroadcastPrivKey(), pkt);
    BOOST_REQUIRE(out.has_value());
    BOOST_CHECK(*out == pt);

    // The broadcast keypair is deterministic across calls.
    BOOST_CHECK(BroadcastPubKey().GetVch() == BroadcastPubKey().GetVch());
}

BOOST_AUTO_TEST_CASE(ecies_infinity_eph_rejected)
{
    // A point-at-infinity ephemeral key forces shared = inf * sk = inf for every
    // sk, i.e. a public-constant AEAD key. Build a packet under exactly that
    // constant secret (encrypt to the infinity pubkey, which yields the same
    // inf shared point) and set the wire eph to infinity. Without a guard this
    // would decrypt under any recipient key; Decrypt must reject it.
    const blsct::PublicKey infinity{}; // default-constructed G1 point == identity
    BOOST_REQUIRE(infinity.GetG1Point().IsZero());

    std::vector<uint8_t> pt{0x01, 0x02, 0x03, 0x04};
    // Outbound guard lives in Transport::Send (Encrypt itself is unchanged so
    // this test can still construct forged packets). Send to the identity must
    // return false without emitting -- see transport_send_rejects_identity.

    // Inbound guard: forge a well-formed packet (encrypted to a real key) but
    // set its wire ephemeral to infinity. Decrypt must reject on the eph
    // check before any key derivation, under any recipient key.
    blsct::PrivateKey victim(BlstScalar::Rand(true));
    EciesPacket pkt = Encrypt(victim.GetPublicKey(), pt);
    pkt.eph = infinity;
    BOOST_CHECK(!Decrypt(victim, pkt).has_value());
    BOOST_CHECK(!Decrypt(BroadcastPrivKey(), pkt).has_value());
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
    //! Envelopes handed to the broadcast callback.
    std::atomic<int> broadcasts{0};

    explicit LoopbackTransport(uint32_t bits) : LoopbackTransport(OptsWithBits(bits)) {}

    explicit LoopbackTransport(Transport::Options opts)
        : pool(WorkerPool::Options{/*num_workers=*/2, /*ring_capacity=*/64})
    {
        t = std::make_unique<Transport>(
            pool,
            /*broadcast=*/[this](bool stem, const Envelope& env) {
                broadcasts.fetch_add(1);
                // Serialize, then feed back in as if received from peer 1.
                DataStream ss;
                ss << env;
                auto bytes = MakeUCharSpan(ss);
                std::vector<uint8_t> v(bytes.begin(), bytes.end());
                t->OnWire(/*from_peer=*/1, stem, v);
            },
            /*relay=*/[](int64_t, bool, bool, const Envelope&) {},
            opts);
        pool.Start();
    }
    ~LoopbackTransport() { pool.Stop(); }

    static Transport::Options OptsWithBits(uint32_t bits)
    {
        Transport::Options opts;
        opts.pow_bits = bits;
        return opts;
    }
};
} // namespace

BOOST_AUTO_TEST_CASE(transport_ping_loopback)
{
    LoopbackTransport h(/*bits=*/4);

    std::atomic<int> pings{0};
    std::vector<uint8_t> got;
    std::mutex gm;
    h.t->RegisterHandler(PayloadKind::PING, RECIPIENTS_PING, [&](const InboundMessage& m) {
        {
            std::lock_guard<std::mutex> lk(gm);
            got = m.body;
        }
        pings.fetch_add(1, std::memory_order_relaxed);
    });

    std::vector<uint8_t> payload{0xde, 0xad, 0xbe, 0xef};
    // Send to our own inbox key (non-PoW kind), broadcast loops it back in.
    BOOST_REQUIRE(h.t->Send(h.t->InboxPubKey(), PayloadKind::PING, payload, /*stem=*/false));

    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (pings.load() < 1 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    BOOST_CHECK_EQUAL(pings.load(), 1);
    std::lock_guard<std::mutex> lk(gm);
    BOOST_CHECK(got == payload);
}

BOOST_AUTO_TEST_CASE(transport_send_rejects_identity)
{
    // Send to the identity/an invalid recipient key must return false without
    // broadcasting -- a network-supplied reply key can be exactly that, and it
    // must never throw (a throw on the candserve thread terminates the node).
    LoopbackTransport h(/*bits=*/4);

    const blsct::PublicKey identity{};
    BOOST_REQUIRE(identity.GetG1Point().IsZero());
    BOOST_CHECK(!Transport::IsValidRecipient(identity));
    BOOST_CHECK(!h.t->Send(identity, PayloadKind::PING, {0x01}, /*stem=*/false));
    BOOST_CHECK_EQUAL(h.broadcasts.load(), 0);

    // A valid recipient still succeeds, and is broadcast exactly once.
    BOOST_CHECK(Transport::IsValidRecipient(h.t->InboxPubKey()));
    BOOST_CHECK(h.t->Send(h.t->InboxPubKey(), PayloadKind::PING, {0x02}, /*stem=*/false));
    BOOST_CHECK_EQUAL(h.broadcasts.load(), 1);
}

BOOST_AUTO_TEST_CASE(transport_send_preserves_submission_order)
{
    // A burst of sends to one recipient -- e.g. a chat app turning several
    // typed lines into several sendp2pmsg calls -- must reach the wire in the
    // order it submitted them. Each Send() grinds the mandatory PoW on its own
    // thread, and a grind is a geometric search whose spread is as large as its
    // mean, so without the send-order gate the emission order is unrelated to
    // the submission order and the recipient stores the burst scrambled. The
    // difficulty here is low for test speed but still far longer than the 2ms
    // submission spacing below, so the grinds overlap and finish out of
    // order; the ordering must hold anyway.
    constexpr uint32_t BITS{15};
    constexpr int MESSAGES{8};

    WorkerPool pool{WorkerPool::Options{/*num_workers=*/1, /*ring_capacity=*/8}};
    Transport::Options opts;
    opts.pow_bits = BITS;

    // Own the recipient key so the broadcast callback can recover which message
    // each envelope carries (its one-byte body is the submission index).
    const blsct::PrivateKey recipient_priv(BlstScalar::Rand(/*exclude_zero=*/true));
    const blsct::PublicKey recipient(recipient_priv.GetPublicKey());

    std::mutex emitted_mutex;
    std::vector<int> emitted;
    Transport t(
        pool,
        /*broadcast=*/[&](bool, const Envelope& env) {
            const uint8_t aad[1] = {env.kind};
            const auto plain = Decrypt(recipient_priv, env.enc, std::span<const uint8_t>{aad, 1});
            // Checked on the main thread below: Boost.Test assertions are not
            // safe to run from these sender threads.
            const int index = (plain && plain->size() == 1) ? static_cast<int>((*plain)[0]) : -1;
            std::lock_guard<std::mutex> lk(emitted_mutex);
            emitted.push_back(index);
        },
        /*relay=*/[](int64_t, bool, bool, const Envelope&) {}, opts);

    std::mutex gate_mutex;
    std::condition_variable gate_cv;
    int released{-1}; //!< highest index allowed to call Send()
    int entered{-1};  //!< highest index that is about to call Send()
    std::vector<uint8_t> sent(MESSAGES, 0);

    std::vector<std::thread> senders;
    senders.reserve(MESSAGES);
    for (int i = 0; i < MESSAGES; ++i) {
        senders.emplace_back([&, i] {
            {
                std::unique_lock<std::mutex> lk(gate_mutex);
                gate_cv.wait(lk, [&] { return released >= i; });
                entered = i;
            }
            gate_cv.notify_all();
            sent[i] = t.Send(recipient, PayloadKind::USER_DATA,
                             {static_cast<uint8_t>(i)}, /*stem=*/false)
                          ? 1
                          : 0;
        });
    }
    // Submit one at a time, waiting for each sender to have claimed its ticket
    // before releasing the next, so the submission order really is 0..N-1.
    for (int i = 0; i < MESSAGES; ++i) {
        {
            std::lock_guard<std::mutex> lk(gate_mutex);
            released = i;
        }
        gate_cv.notify_all();
        {
            std::unique_lock<std::mutex> lk(gate_mutex);
            gate_cv.wait(lk, [&] { return entered >= i; });
        }
        // Wait for the sender to have actually CLAIMED its ticket, not merely
        // to be about to call Send(): the claim happens inside Send(), behind
        // IsValidRecipient(). The previous version bridged that gap with a 2 ms
        // sleep, which made the test a race rather than a check -- a thread
        // descheduled across those 2 ms claims late, two sends swap places, and
        // the compare fails. That is how this failed on the 32-bit ARM runner.
        const uint64_t want = static_cast<uint64_t>(i) + 1;
        BOOST_REQUIRE_MESSAGE(WaitFor([&] { return t.SendTicketsIssued() >= want; }),
                              "sender " << i << " never claimed its send ticket");
    }
    for (auto& th : senders) th.join();

    std::vector<int> expected(MESSAGES);
    std::iota(expected.begin(), expected.end(), 0);
    BOOST_CHECK_EQUAL_COLLECTIONS(emitted.begin(), emitted.end(), expected.begin(), expected.end());
    for (int i = 0; i < MESSAGES; ++i) BOOST_CHECK_MESSAGE(sent[i] == 1, "send " << i << " failed");
}

BOOST_AUTO_TEST_CASE(transport_inbox_rotation)
{
    // Inbox-prekey rotation: the current prekey changes each epoch, a grace ring
    // of one previous prekey keeps messages sent to the just-rotated prekey
    // decryptable, and prekeys older than the grace window stop decrypting (which
    // is what bounds a key-extraction's decryption window). The stable identity
    // is unchanged by rotation, and the published prekey stays authenticated.
    Transport::Options opts;
    opts.pow_bits = 4;
    opts.prekey_rotation_secs = 100;
    opts.prekey_grace_keys = 1;
    LoopbackTransport h(opts);
    h.t->now_override = 1000;

    std::atomic<int> pings{0};
    h.t->RegisterHandler(PayloadKind::PING, RECIPIENTS_PING,
                         [&](const InboundMessage&) { pings.fetch_add(1, std::memory_order_relaxed); });

    auto wait_pings = [&](int want) {
        using namespace std::chrono_literals;
        auto deadline = std::chrono::steady_clock::now() + 5s;
        while (pings.load() < want && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(1ms);
        }
    };
    // Confirm a send did NOT decrypt: wait a beat, assert the counter is steady.
    auto expect_no_ping = [&](int steady) {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(200ms);
        BOOST_CHECK_EQUAL(pings.load(), steady);
    };

    const blsct::PublicKey k0 = h.t->InboxPubKey();
    const blsct::PublicKey id0 = h.t->IdentityPubKey();
    // The identity is stable across rotations, and the published prekey signature
    // authenticates the CURRENT prekey under that identity.
    auto bundle_ok = [&] {
        BOOST_CHECK(h.t->IdentityPubKey().GetVch() == id0.GetVch());
        BOOST_CHECK(id0.Verify(h.t->InboxPubKey().GetVch(), h.t->PrekeySig()));
    };
    bundle_ok();

    // First tick baselines the rotation clock at t=1000 (no rotation yet).
    h.t->MaybeRotatePrekey();
    BOOST_CHECK(h.t->InboxPubKey().GetVch() == k0.GetVch());

    // Not yet due -> no rotation.
    h.t->now_override = 1099;
    h.t->MaybeRotatePrekey();
    BOOST_CHECK(h.t->InboxPubKey().GetVch() == k0.GetVch());

    // Interval elapsed -> rotate. k0 moves into the grace ring.
    h.t->now_override = 1100;
    h.t->MaybeRotatePrekey();
    const blsct::PublicKey k1 = h.t->InboxPubKey();
    BOOST_CHECK(k1.GetVch() != k0.GetVch());
    bundle_ok(); // identity unchanged; sig now covers k1

    // A message to the rotated-out k0 still decrypts (grace ring, depth 1).
    BOOST_REQUIRE(h.t->Send(k0, PayloadKind::PING, {1}, /*stem=*/false));
    wait_pings(1);
    BOOST_CHECK_EQUAL(pings.load(), 1);

    // A message to the current key k1 decrypts.
    BOOST_REQUIRE(h.t->Send(k1, PayloadKind::PING, {2}, /*stem=*/false));
    wait_pings(2);
    BOOST_CHECK_EQUAL(pings.load(), 2);

    // Rotate again: with grace depth 1, k0 falls out of the ring (only k1 kept).
    h.t->now_override = 1200;
    h.t->MaybeRotatePrekey();
    const blsct::PublicKey k2 = h.t->InboxPubKey();
    BOOST_CHECK(k2.GetVch() != k1.GetVch());
    bundle_ok(); // identity unchanged; sig now covers k2

    // k0 is now beyond the grace window: a message to it no longer decrypts.
    BOOST_REQUIRE(h.t->Send(k0, PayloadKind::PING, {3}, /*stem=*/false));
    expect_no_ping(2);

    // The current key still works.
    BOOST_REQUIRE(h.t->Send(k2, PayloadKind::PING, {4}, /*stem=*/false));
    wait_pings(3);
    BOOST_CHECK_EQUAL(pings.load(), 3);
}

BOOST_AUTO_TEST_CASE(transport_recipient_key_tagging)
{
    // Handlers gate on which local key decrypted a message (e.g. CANDIDATE_TX
    // only accepts SESSION), so the tag must reflect the actual decrypt path.
    LoopbackTransport h(/*bits=*/4);

    std::atomic<int> got{0};
    std::mutex gm;
    std::vector<RecipientKey> tags;
    // Accept every class: this test is about the tag, not the gate.
    h.t->RegisterHandler(PayloadKind::PING, {.inbox = true, .broadcast = true, .session = true}, [&](const InboundMessage& m) {
        {
            std::lock_guard<std::mutex> lk(gm);
            tags.push_back(m.recipient);
        }
        got.fetch_add(1, std::memory_order_relaxed);
    });

    using namespace std::chrono_literals;
    auto wait_for = [&](int n) {
        auto deadline = std::chrono::steady_clock::now() + 10s;
        while (got.load() < n && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(1ms);
        }
        BOOST_REQUIRE_EQUAL(got.load(), n);
    };

    // Inbox-encrypted -> INBOX.
    BOOST_REQUIRE(h.t->Send(h.t->InboxPubKey(), PayloadKind::PING, {1}, /*stem=*/false));
    wait_for(1);
    // Broadcast-encrypted -> BROADCAST.
    BOOST_REQUIRE(h.t->Send(BroadcastPubKey(), PayloadKind::PING, {2}, /*stem=*/false));
    wait_for(2);
    // Encrypted to a registered session key -> SESSION.
    blsct::PrivateKey sess_priv(BlstScalar::Rand(/*exclude_zero=*/true));
    blsct::PublicKey sess_pub = sess_priv.GetPublicKey();
    h.t->AddSessionKey(sess_pub, sess_priv, /*expiry=*/0);
    BOOST_REQUIRE(h.t->Send(sess_pub, PayloadKind::PING, {3}, /*stem=*/false));
    wait_for(3);

    std::lock_guard<std::mutex> lk(gm);
    BOOST_REQUIRE_EQUAL(tags.size(), 3U);
    BOOST_CHECK(tags[0] == RecipientKey::INBOX);
    BOOST_CHECK(tags[1] == RecipientKey::BROADCAST);
    BOOST_CHECK(tags[2] == RecipientKey::SESSION);
}

BOOST_AUTO_TEST_CASE(transport_allowed_recipients_per_kind)
{
    // Every built-in kind, registered with its production set, sent under
    // each local key class: only the classes the set names reach a handler.
    // The expected table is written out here rather than derived from the
    // RECIPIENTS_* constants, so a wrong constant fails this test.
    LoopbackTransport h(/*bits=*/4);

    struct Row {
        PayloadKind kind;
        AllowedRecipients registered;
        AllowedRecipients expected;
    };
    const std::vector<Row> rows{
        {PayloadKind::PING, RECIPIENTS_PING, {.inbox = true}},
        {PayloadKind::AGG_ANN, RECIPIENTS_AGG_ANN, {.broadcast = true}},
        {PayloadKind::RFQ_REQ, RECIPIENTS_RFQ_REQ, {.broadcast = true}},
        {PayloadKind::ORDER_ANN, RECIPIENTS_ORDER_ANN, {.broadcast = true}},
        {PayloadKind::CANDIDATE_TX, RECIPIENTS_CANDIDATE_TX, {.session = true}},
        {PayloadKind::RFQ_QUOTE, RECIPIENTS_RFQ_QUOTE, {.session = true}},
        {PayloadKind::USER_DATA, RECIPIENTS_USER_DATA, {.inbox = true, .broadcast = true, .user_reply = true}},
    };

    // One delivery counter per (kind, key class). Each send carries its key
    // class as its one-byte body, so a handler can tell which it came under.
    enum KeyClass : uint8_t { INBOX, BROADCAST, SESSION, USER_REPLY, NUM_CLASSES };
    std::array<std::array<std::atomic<int>, NUM_CLASSES>, 256> got{};
    std::array<std::atomic<bool>, 256> flag_ok{};
    for (const Row& row : rows) {
        flag_ok[static_cast<uint8_t>(row.kind)] = true;
        h.t->RegisterHandler(row.kind, row.registered, [&](const InboundMessage& m) {
            const uint8_t k = static_cast<uint8_t>(m.kind);
            if (m.body.size() != 1 || m.body[0] >= NUM_CLASSES) {
                flag_ok[k] = false;
                return;
            }
            // The flag a handler sees must match the class it was sent under.
            if (m.recipient_user_reply != (m.body[0] == USER_REPLY)) flag_ok[k] = false;
            got[k][m.body[0]].fetch_add(1, std::memory_order_relaxed);
        });
    }

    blsct::PrivateKey session_priv(BlstScalar::Rand(/*exclude_zero=*/true));
    const blsct::PublicKey session_pub = session_priv.GetPublicKey();
    BOOST_REQUIRE(h.t->AddSessionKey(session_pub, session_priv, /*expiry=*/0));
    blsct::PrivateKey reply_priv(BlstScalar::Rand(/*exclude_zero=*/true));
    const blsct::PublicKey reply_pub = reply_priv.GetPublicKey();
    BOOST_REQUIRE(h.t->AddSessionKey(reply_pub, reply_priv, /*expiry=*/0, Transport::SessionPurpose::USER_REPLY));
    const std::array<blsct::PublicKey, NUM_CLASSES> keys{h.t->InboxPubKey(), BroadcastPubKey(), session_pub, reply_pub};

    for (const Row& row : rows) {
        for (uint8_t c = 0; c < NUM_CLASSES; ++c) {
            BOOST_REQUIRE(h.t->Send(keys[c], row.kind, {c}, /*stem=*/false));
        }
    }

    // Every send is one decrypt job, enqueued synchronously by the loopback.
    // Waiting for all of them to complete makes the "dropped" counts final
    // rather than a race against a worker that has not run yet.
    BOOST_REQUIRE_EQUAL(h.pool.Submitted(), rows.size() * NUM_CLASSES);
    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 10s;
    while (h.pool.Completed() < h.pool.Submitted() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    BOOST_REQUIRE_EQUAL(h.pool.Completed(), h.pool.Submitted());

    for (const Row& row : rows) {
        const uint8_t k = static_cast<uint8_t>(row.kind);
        const std::array<bool, NUM_CLASSES> want{row.expected.inbox, row.expected.broadcast,
                                                 row.expected.session, row.expected.user_reply};
        for (uint8_t c = 0; c < NUM_CLASSES; ++c) {
            BOOST_TEST_INFO("kind " << int{k} << " key class " << int{c});
            BOOST_CHECK_EQUAL(got[k][c].load(), want[c] ? 1 : 0);
        }
        BOOST_CHECK_MESSAGE(flag_ok[k].load(), "kind " << int{k} << " saw a wrong body or recipient_user_reply");
    }
}

BOOST_AUTO_TEST_CASE(transport_kind_registered_with_no_recipients_gets_nothing)
{
    // Default deny: an empty set accepts no key class at all.
    LoopbackTransport h(/*bits=*/4);
    std::atomic<int> handled{0};
    h.t->RegisterHandler(PayloadKind::PING, AllowedRecipients{}, [&](const InboundMessage&) {
        handled.fetch_add(1, std::memory_order_relaxed);
    });
    BOOST_REQUIRE(h.t->Send(h.t->InboxPubKey(), PayloadKind::PING, {1}, /*stem=*/false));
    BOOST_REQUIRE(h.t->Send(BroadcastPubKey(), PayloadKind::PING, {2}, /*stem=*/false));

    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 10s;
    while (h.pool.Completed() < 2 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    BOOST_REQUIRE_EQUAL(h.pool.Completed(), 2U);
    BOOST_CHECK_EQUAL(handled.load(), 0);
}

BOOST_AUTO_TEST_CASE(transport_pow_kind_loopback)
{
    LoopbackTransport h(/*bits=*/6);

    std::atomic<int> reqs{0};
    h.t->RegisterHandler(PayloadKind::RFQ_REQ, RECIPIENTS_RFQ_REQ, [&](const InboundMessage&) {
        reqs.fetch_add(1, std::memory_order_relaxed);
    });

    BOOST_REQUIRE(h.t->Send(BroadcastPubKey(), PayloadKind::RFQ_REQ, {1, 2, 3}, /*stem=*/true));

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
                         std::vector<uint8_t> payload, uint32_t bits, int64_t now,
                         std::vector<uint8_t> flag = {})
{
    Envelope env;
    env.kind = static_cast<uint8_t>(kind);
    // Bind the kind byte as AEAD associated data, matching Transport::Send.
    const uint8_t aad[1] = {env.kind};
    env.enc = Encrypt(inbox, payload, std::span<const uint8_t>{aad, 1});
    env.flag = std::move(flag);
    env.pow.version = POW_VERSION_CURRENT;
    env.pow.timestamp = now;
    env.pow.kind = env.kind;
    env.pow.session_eph = env.enc.eph;
    env.pow.payload_hash = env.ExpectedPayloadHash();
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
    h.t->RegisterHandler(PayloadKind::PING, RECIPIENTS_PING, [&](const InboundMessage&) {});

    auto env = StampedEnvelope(h.t->InboxPubKey(), PayloadKind::PING, {7, 7}, /*bits=*/4, /*now=*/1000);
    auto v = SerEnv(env);

    auto r1 = h.t->OnWire(1, false, v);
    auto r2 = h.t->OnWire(1, false, v);
    BOOST_CHECK(r1 == Transport::WireResult::Enqueued);
    BOOST_CHECK(r2 == Transport::WireResult::RejectReplay);
}

BOOST_AUTO_TEST_CASE(transport_session_key_decrypts)
{
    LoopbackTransport h(/*bits=*/4);
    h.t->now_override = 1000;

    std::atomic<int> pings{0};
    h.t->RegisterHandler(PayloadKind::PING, {.session = true}, [&](const InboundMessage&) {
        pings.fetch_add(1, std::memory_order_relaxed);
    });

    // A fresh per-request session keypair, distinct from the node inbox key.
    blsct::PrivateKey reply_priv(BlstScalar::Rand(true));
    blsct::PublicKey reply_key = reply_priv.GetPublicKey();

    // Registered and live: a message encrypted to it decrypts and dispatches.
    // (Register before sending — a pre-registration send would race the async
    // worker, which might run after AddSessionKey and decrypt it after all.)
    h.t->AddSessionKey(reply_key, reply_priv, /*expiry=*/2000);
    auto env_ok = StampedEnvelope(reply_key, PayloadKind::PING, {1, 1}, /*bits=*/4, /*now=*/1000);
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(env_ok)) == Transport::WireResult::Enqueued);

    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (pings.load() < 1 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    BOOST_CHECK_EQUAL(pings.load(), 1);

    // Expired session key: filtered out at decrypt time by the expiry check, so
    // the result is independent of worker timing (no race). Advance past the
    // 2000 expiry and confirm a message to the same key is never dispatched.
    h.t->now_override = 3000;
    auto env_expired = StampedEnvelope(reply_key, PayloadKind::PING, {2, 2}, /*bits=*/4, /*now=*/3000);
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(env_expired)) == Transport::WireResult::Enqueued);
    std::this_thread::sleep_for(200ms); // let the worker (fail to) process it
    BOOST_CHECK_EQUAL(pings.load(), 1); // still 1 — expired key did not decrypt
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
    const int64_t now_ov = h.t->now_override.load();
    env.pow.timestamp = now_ov ? now_ov : 1;
    env.pow.session_eph = env.enc.eph;
    env.pow.payload_hash = env.ExpectedPayloadHash();
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
        [](bool, const Envelope&) {},
        [&](int64_t origin, bool, bool, const Envelope&) { relay_origin = origin; relayed.fetch_add(1); },
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

BOOST_AUTO_TEST_CASE(user_inbox_size_cap_prunes)
{
    // A memory_only store with a tiny byte cap: after inserting well past the
    // cap, TotalBytes() must stay within the inbox scope's share of it and
    // equal the sum of what List() still returns. Catches PruneLocked
    // double-subtracting (which drives the persisted total below reality and
    // disarms the cap).
    // Every entry is MsgScope::INBOX, so this covers one scope's oldest-first
    // eviction only; user_inbox_scopes_have_separate_budgets covers how the
    // scopes' budgets interact.
    UserInbox::Options opts;
    opts.memory_only = true;
    opts.max_total_bytes = 4096;
    opts.expiry_seconds = 0;
    UserInbox inbox(opts);

    const blsct::PublicKey sender = blsct::PrivateKey(BlstScalar::Rand(true)).GetPublicKey();
    const std::vector<uint8_t> body(256, 0xab);
    for (int i = 0; i < 200; ++i) {
        inbox.Add(1000 + i, MsgScope::INBOX, "t", sender, body);
    }
    BOOST_CHECK_LE(inbox.TotalBytes(), UserInbox::ScopeCapBytes(opts.max_total_bytes, MsgScope::INBOX));

    // TotalBytes() must equal exactly (retained count) x (one entry's bytes),
    // measured from a fresh store so the check is independent of EntryBytes
    // internals. A drifted counter (the prune double-subtract) breaks this.
    const auto all = inbox.List(0, 0, "");
    UserInbox::Options ref = opts;
    UserInbox unit(ref);
    unit.Add(1, MsgScope::INBOX, "t", sender, body);
    BOOST_CHECK_EQUAL(inbox.Size(), all.size());
    BOOST_CHECK_EQUAL(inbox.TotalBytes(), all.size() * unit.TotalBytes());
    // ids are monotonic and the newest survive.
    if (!all.empty()) BOOST_CHECK_EQUAL(all.back().id, 200u);
}

BOOST_AUTO_TEST_CASE(user_inbox_scopes_have_separate_budgets)
{
    // Each scope is pruned against its own share of the cap, so flooding any
    // one scope must leave every entry of another in place, however old --
    // anyone holding the inbox prekey must not be able to evict session
    // replies, nor a subscribed-topic flood unread 1:1 messages. The victims
    // are inserted first, so a scope-blind oldest-first prune evicts them.
    const std::array<MsgScope, NUM_MSG_SCOPES> scopes{MsgScope::INBOX, MsgScope::BROADCAST, MsgScope::SESSION};
    const blsct::PublicKey sender = blsct::PrivateKey(BlstScalar::Rand(true)).GetPublicKey();
    const std::vector<uint8_t> body(64, 0x7);
    constexpr size_t VICTIMS{3};

    UserInbox::Options opts;
    opts.memory_only = true;
    opts.max_total_bytes = 8192;
    opts.expiry_seconds = 0;
    // One entry's bytes, measured from a fresh store (see
    // user_inbox_size_cap_prunes); every entry below is the same size.
    UserInbox unit(opts);
    unit.Add(1, MsgScope::INBOX, "t", sender, body);
    const uint64_t entry_bytes = unit.TotalBytes();

    for (const MsgScope victim : scopes) {
        // The victims must fit their own budget, or they are not victims.
        BOOST_REQUIRE_LE(VICTIMS * entry_bytes, UserInbox::ScopeCapBytes(opts.max_total_bytes, victim));
        for (const MsgScope flooder : scopes) {
            if (flooder == victim) continue;
            BOOST_TEST_INFO("victim " << int{static_cast<uint8_t>(victim)} << " flooder " << int{static_cast<uint8_t>(flooder)});
            UserInbox inbox(opts);
            for (size_t i = 0; i < VICTIMS; ++i) inbox.Add(1000, victim, "t", sender, body);
            for (int i = 0; i < 200; ++i) inbox.Add(2000 + i, flooder, "t", sender, body);

            size_t victims_kept{0}, flood_kept{0};
            for (const auto& e : inbox.List(0, 0, "")) {
                if (e.scope == static_cast<uint8_t>(victim)) ++victims_kept;
                if (e.scope == static_cast<uint8_t>(flooder)) ++flood_kept;
            }
            BOOST_CHECK_EQUAL(victims_kept, VICTIMS);
            // The flood was pruned, and to its own budget: the newest survive.
            BOOST_CHECK_GT(flood_kept, 0U);
            BOOST_CHECK_LE(flood_kept * entry_bytes, UserInbox::ScopeCapBytes(opts.max_total_bytes, flooder));
            BOOST_CHECK_EQUAL(inbox.LastId(), VICTIMS + 200);
            BOOST_CHECK_EQUAL(inbox.List(0, 0, "").back().id, VICTIMS + 200);
        }
    }
}

BOOST_AUTO_TEST_CASE(user_inbox_scope_budgets_survive_reopen)
{
    // The per-scope byte counts are rebuilt from the entries when the store is
    // opened. Fill the inbox budget to its steady state, reopen, add one more:
    // it must evict the oldest, not grow the scope past its budget as it would
    // if the reopened store counted the scope as empty.
    const blsct::PublicKey sender = blsct::PrivateKey(BlstScalar::Rand(true)).GetPublicKey();
    const std::vector<uint8_t> body(64, 0x7);
    UserInbox::Options opts;
    opts.path = m_path_root / "user_inbox_reopen";
    opts.max_total_bytes = 8192;
    opts.expiry_seconds = 0;

    size_t steady{0};
    {
        UserInbox inbox(opts);
        for (int i = 0; i < 200; ++i) inbox.Add(1000 + i, MsgScope::INBOX, "t", sender, body);
        steady = inbox.Size();
        BOOST_REQUIRE_LT(steady, 200U);
    }
    UserInbox inbox(opts);
    BOOST_REQUIRE_EQUAL(inbox.Size(), steady);
    inbox.Add(2000, MsgScope::INBOX, "t", sender, body);
    BOOST_CHECK_EQUAL(inbox.Size(), steady);
    BOOST_CHECK_EQUAL(inbox.List(0, 0, "").size(), steady);
}

BOOST_AUTO_TEST_CASE(user_inbox_expiry_prunes)
{
    UserInbox::Options opts;
    opts.memory_only = true;
    opts.max_total_bytes = 0; // no size cap; isolate expiry
    opts.expiry_seconds = 100;
    UserInbox inbox(opts);

    const blsct::PublicKey sender = blsct::PrivateKey(BlstScalar::Rand(true)).GetPublicKey();
    const std::vector<uint8_t> body(64, 0x01);
    const int64_t now = GetTime<std::chrono::seconds>().count();
    // Two entries older than expiry_seconds, one fresh. Prune runs at each
    // Add with now = the received_at argument; List also filters on the real
    // clock, so anchor everything near real now.
    inbox.Add(now - 1000, MsgScope::INBOX, "t", sender, body);
    inbox.Add(now - 1000, MsgScope::INBOX, "t", sender, body);
    inbox.Add(now, MsgScope::INBOX, "t", sender, body);
    // The two ancient entries are now > expiry_seconds old and must be gone.
    // One fresh entry survives; the two expired are pruned.
    BOOST_CHECK_EQUAL(inbox.Size(), 1u);
    // TotalBytes must equal exactly one entry's worth. The prune
    // double-subtract bug drove the persisted total below the true value
    // (here it would have underflowed to a huge number after subtracting the
    // two expired entries twice); pin it to a single-entry baseline measured
    // from a fresh store so the check is independent of EntryBytes internals.
    UserInbox::Options ref = opts;
    UserInbox one(ref);
    one.Add(now, MsgScope::INBOX, "t", sender, body);
    BOOST_CHECK_EQUAL(inbox.TotalBytes(), one.TotalBytes());
}

namespace {
//! A USER_DATA payload: the serialized frame the handler parses.
std::vector<uint8_t> UserDataPayload(const std::string& topic, const std::vector<uint8_t>& body)
{
    DataStream ss;
    ss << UserMsgFrame{topic, body};
    const auto bytes = MakeUCharSpan(ss);
    return {bytes.begin(), bytes.end()};
}
} // namespace

BOOST_AUTO_TEST_CASE(user_data_handler_stores_only_accepted_recipients)
{
    // The production USER_DATA registration, end to end over the loopback:
    // a message encrypted to an INTERNAL session key (a candidate-pull or RFQ
    // reply key, which the node broadcasts on the bus) must never reach the
    // store or the notifiers, while the same message to a minted user reply
    // key is stored as "session" with its reply key. An unsubscribed
    // broadcast topic is dropped too.
    LoopbackTransport h(/*bits=*/4);
    UserInbox::Options opts;
    opts.memory_only = true;
    UserInbox inbox(opts);
    BOOST_REQUIRE(inbox.Subscribe("pub"));
    std::atomic<int> notified{0};
    RegisterUserDataHandler(*h.t, inbox, [&](const UserInbox::Entry&) {
        notified.fetch_add(1, std::memory_order_relaxed);
    });

    blsct::PrivateKey internal_priv(BlstScalar::Rand(/*exclude_zero=*/true));
    const blsct::PublicKey internal_pub = internal_priv.GetPublicKey();
    BOOST_REQUIRE(h.t->AddSessionKey(internal_pub, internal_priv, /*expiry=*/0));
    blsct::PrivateKey reply_priv(BlstScalar::Rand(/*exclude_zero=*/true));
    const blsct::PublicKey reply_pub = reply_priv.GetPublicKey();
    BOOST_REQUIRE(h.t->AddSessionKey(reply_pub, reply_priv, /*expiry=*/0, Transport::SessionPurpose::USER_REPLY));

    const std::vector<std::pair<blsct::PublicKey, std::string>> sends{
        {internal_pub, "injected"},
        {h.t->InboxPubKey(), "inbox"},
        {reply_pub, "reply"},
        {BroadcastPubKey(), "pub"},
        {BroadcastPubKey(), "unsubscribed"},
    };
    for (const auto& [key, topic] : sends) {
        BOOST_REQUIRE(h.t->Send(key, PayloadKind::USER_DATA, UserDataPayload(topic, {0x42}), /*stem=*/false));
    }
    // Every send is one decrypt job; wait for all of them so the dropped ones
    // are final rather than not yet run.
    BOOST_REQUIRE_EQUAL(h.pool.Submitted(), sends.size());
    using namespace std::chrono_literals;
    auto deadline = std::chrono::steady_clock::now() + 10s;
    while (h.pool.Completed() < h.pool.Submitted() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
    BOOST_REQUIRE_EQUAL(h.pool.Completed(), h.pool.Submitted());

    std::map<std::string, UserInbox::Entry> by_topic;
    for (auto& e : inbox.List(0, 0, "")) by_topic.emplace(e.topic, std::move(e));
    BOOST_CHECK(!by_topic.contains("injected"));
    BOOST_CHECK(!by_topic.contains("unsubscribed"));
    BOOST_REQUIRE_EQUAL(by_topic.size(), 3U);
    BOOST_CHECK_EQUAL(by_topic.at("inbox").scope, static_cast<uint8_t>(MsgScope::INBOX));
    BOOST_CHECK(by_topic.at("inbox").reply_pubkey.empty());
    BOOST_CHECK_EQUAL(by_topic.at("reply").scope, static_cast<uint8_t>(MsgScope::SESSION));
    BOOST_CHECK(by_topic.at("reply").reply_pubkey == reply_pub.GetVch());
    BOOST_CHECK_EQUAL(by_topic.at("pub").scope, static_cast<uint8_t>(MsgScope::BROADCAST));
    BOOST_CHECK_EQUAL(notified.load(), 3);
}

BOOST_AUTO_TEST_CASE(user_data_handler_drops_malformed_frames)
{
    // Frames the handler must refuse before they reach the store: each
    // network-controlled field it validates, one at a time, with a
    // well-formed message last to show the same path does store.
    UserInbox::Options opts;
    opts.memory_only = true;
    UserInbox inbox(opts);
    const blsct::PublicKey sender = blsct::PrivateKey(BlstScalar::Rand(true)).GetPublicKey();
    auto message = [&](std::vector<uint8_t> body) {
        InboundMessage m{.kind = PayloadKind::USER_DATA, .from_peer = 1, .sender_session = sender};
        m.recipient = RecipientKey::INBOX;
        m.body = std::move(body);
        return m;
    };

    std::vector<uint8_t> trailing = UserDataPayload("t", {0x01});
    trailing.push_back(0x00);
    const std::vector<std::pair<std::string, std::vector<uint8_t>>> rejected{
        {"empty payload", {}},
        {"oversized payload", std::vector<uint8_t>(MAX_USER_MSG_BYTES + 1, 0x01)},
        {"truncated frame", {0x05, 't'}},
        {"trailing bytes", trailing},
        {"empty topic", UserDataPayload("", {0x01})},
        {"non-printable topic", UserDataPayload("t\n", {0x01})},
        {"non-ASCII topic", UserDataPayload("t\xff", {0x01})},
        {"empty body", UserDataPayload("t", {})},
    };
    for (const auto& [what, payload] : rejected) {
        BOOST_TEST_INFO(what);
        BOOST_CHECK(!StoreUserData(message(payload), inbox, /*now=*/1000));
    }
    BOOST_CHECK_EQUAL(inbox.Size(), 0U);

    const auto stored = StoreUserData(message(UserDataPayload("t", {0x01})), inbox, /*now=*/1000);
    BOOST_REQUIRE(stored);
    BOOST_CHECK_EQUAL(stored->topic, "t");
    BOOST_CHECK(stored->payload == std::vector<uint8_t>{0x01});
    BOOST_CHECK_EQUAL(inbox.Size(), 1U);
}

BOOST_AUTO_TEST_CASE(envelope_v2_carries_and_binds_a_detection_flag)
{
    // A flagged envelope is accepted, relayed with the flag INTACT (a relay
    // that dropped it would silently deny the recipient offline delivery), and
    // the flag still tests against the recipient's detection key after the
    // round trip through serialization and relay.
    WorkerPool pool{WorkerPool::Options{/*num_workers=*/1, /*ring_capacity=*/16}};
    std::vector<uint8_t> relayed_flag;
    std::atomic<int> relays{0};
    auto t = std::make_unique<Transport>(
        pool, [](bool, const Envelope&) {},
        [&](int64_t, bool, bool, const Envelope& e) {
            relayed_flag = e.flag;
            relays.fetch_add(1, std::memory_order_relaxed);
        },
        LoopbackTransport::OptsWithBits(4));
    t->now_override = 1000;

    const auto sk = FmdSecretKey::Random();
    const auto flag = FmdFlag(sk.GetClueKey());
    auto env = StampedEnvelope(t->InboxPubKey(), PayloadKind::PING, {1}, /*bits=*/4,
                               /*now=*/1000, flag);
    BOOST_CHECK_EQUAL(env.flag.size(), FMD_FLAG_SIZE);
    BOOST_CHECK(t->OnWire(1, false, SerEnv(env)) == Transport::WireResult::Enqueued);
    BOOST_CHECK_EQUAL(relays.load(), 1);
    BOOST_CHECK(relayed_flag == flag);
    BOOST_CHECK(FmdTest(sk.Extract(FMD_GAMMA), relayed_flag));
}

BOOST_AUTO_TEST_CASE(envelope_v2_flag_is_bound_by_the_proof_of_work)
{
    // The whole point of folding the flag into payload_hash: a relay cannot
    // strip the flag (denying offline delivery) or rewrite it into someone
    // else's detection bucket while reusing the original grind.
    LoopbackTransport h(/*bits=*/4);
    h.t->now_override = 1000;

    const auto sk = FmdSecretKey::Random();
    auto env = StampedEnvelope(h.t->InboxPubKey(), PayloadKind::PING, {1}, /*bits=*/4,
                               /*now=*/1000, FmdFlag(sk.GetClueKey()));

    auto stripped = env;
    stripped.flag.clear();
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(stripped)) == Transport::WireResult::RejectPoW);

    auto swapped = env;
    swapped.flag = FmdFlag(FmdSecretKey::Random().GetClueKey());
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(swapped)) == Transport::WireResult::RejectPoW);

    auto tweaked = env;
    tweaked.flag[0] ^= 0x01;
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(tweaked)) == Transport::WireResult::RejectPoW);

    // The untouched original is still fine.
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(env)) == Transport::WireResult::Enqueued);
}

BOOST_AUTO_TEST_CASE(envelope_v2_rejects_legacy_pow_version)
{
    // v1 bound the ciphertext alone. Accepting both versions would let a v1
    // stamp be reused for a v2 envelope carrying an attacker's flag.
    LoopbackTransport h(/*bits=*/4);
    h.t->now_override = 1000;

    Envelope env;
    env.kind = static_cast<uint8_t>(PayloadKind::PING);
    const uint8_t aad[1] = {env.kind};
    env.enc = Encrypt(h.t->InboxPubKey(), std::vector<uint8_t>{1}, std::span<const uint8_t>{aad, 1});
    env.pow.version = POW_VERSION_LEGACY;
    env.pow.timestamp = 1000;
    env.pow.kind = env.kind;
    env.pow.session_eph = env.enc.eph;
    env.pow.payload_hash = PayloadHash(POW_VERSION_LEGACY, env.enc.MsgHash(), {});
    Grind(env.pow, /*bits=*/4);
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(env)) == Transport::WireResult::RejectInvalid);

    // And the two payload hashes genuinely differ for an empty flag, so the
    // versions cannot collide.
    BOOST_CHECK(PayloadHash(POW_VERSION_LEGACY, env.enc.MsgHash(), {}) !=
                PayloadHash(POW_VERSION_FLAGGED, env.enc.MsgHash(), {}));
}

BOOST_AUTO_TEST_CASE(envelope_v2_bounds_the_flag_size)
{
    // Unknown flag sizes are reserved and relayed unchanged (kind-blind relay
    // applies to flags too, so a future gamma propagates without a node
    // upgrade) but the size is bounded so envelope overhead stays predictable.
    LoopbackTransport h(/*bits=*/4);
    h.t->now_override = 1000;

    auto reserved = StampedEnvelope(h.t->InboxPubKey(), PayloadKind::PING, {1}, /*bits=*/4,
                                    /*now=*/1000, std::vector<uint8_t>(16, 0xab));
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(reserved)) == Transport::WireResult::Enqueued);

    auto oversized = StampedEnvelope(h.t->InboxPubKey(), PayloadKind::PING, {2}, /*bits=*/4,
                                     /*now=*/1000, std::vector<uint8_t>(MAX_FLAG_BYTES + 1, 0xab));
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(oversized)) == Transport::WireResult::RejectInvalid);
}

BOOST_AUTO_TEST_CASE(envelope_v2_replay_key_ignores_the_flag)
{
    // Same ciphertext, different flag = still a replay, and dropped.
    //
    // This used to be allowed, on the grounds that it lets a sender re-flag a
    // retransmission for a recipient whose clue key rotated, and that each
    // variant costs a fresh grind. The cost is on the wrong party: the grind
    // is paid once, by anyone, over a ciphertext they did not create, and buys
    // a full relay flood plus a second delivery into the recipient's inbox.
    // The replay cache exists precisely to stop one message being re-minted
    // into many, and a retrieval hint must not be able to defeat it.
    //
    // A sender that genuinely needs to re-flag after a rotation re-encrypts,
    // which is a new ciphertext and a new message -- the honest path, and the
    // one that keeps the cost with whoever is creating the traffic.
    LoopbackTransport h(/*bits=*/4);
    h.t->now_override = 1000;

    const auto a = FmdSecretKey::Random();
    const auto b = FmdSecretKey::Random();
    auto env_a = StampedEnvelope(h.t->InboxPubKey(), PayloadKind::PING, {9}, /*bits=*/4,
                                 /*now=*/1000, FmdFlag(a.GetClueKey()));
    // Reuse the SAME ciphertext with a different flag and a fresh grind.
    auto env_b = env_a;
    env_b.flag = FmdFlag(b.GetClueKey());
    env_b.pow.payload_hash = env_b.ExpectedPayloadHash();
    env_b.pow.nonce = 0;
    Grind(env_b.pow, /*bits=*/4);

    BOOST_CHECK(env_a.enc.MsgHash() == env_b.enc.MsgHash());
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(env_a)) == Transport::WireResult::Enqueued);
    // Re-flagged and re-ground, but the same ciphertext: not a new message.
    BOOST_CHECK_MESSAGE(h.t->OnWire(1, false, SerEnv(env_b)) != Transport::WireResult::Enqueued,
                        "a re-flagged copy of an existing ciphertext was accepted as new");
    // And the identical envelope is still a replay.
    BOOST_CHECK(h.t->OnWire(1, false, SerEnv(env_a)) != Transport::WireResult::Enqueued);
}

BOOST_AUTO_TEST_CASE(transport_publishes_a_signed_clue_key_that_rotates)
{
    LoopbackTransport h(/*bits=*/4);
    const auto ck = h.t->FmdClueKeyBytes();
    BOOST_CHECK_EQUAL(ck.size(), FMD_CLUE_KEY_SIZE);
    BOOST_REQUIRE(FmdClueKey::FromBytes(ck).has_value());
    // A sender must be able to authenticate a fetched clue key before flagging
    // to it; flagging to a substituted key hands the retrieval side away.
    BOOST_CHECK(h.t->IdentityPubKey().Verify(ck, h.t->FmdSig()));

    // The node can detect a message flagged to its own published clue key.
    const auto flag = FmdFlag(*FmdClueKey::FromBytes(ck));
    BOOST_CHECK(FmdTest(h.t->FmdDetectionKey(FMD_GAMMA), flag));

    // Rotating the prekey rotates the clue key with it, so detection keys
    // handed out under the old one stop matching -- that bounds their lifetime.
    h.t->RotatePrekey();
    const auto ck2 = h.t->FmdClueKeyBytes();
    BOOST_CHECK(ck2 != ck);
    BOOST_CHECK(h.t->IdentityPubKey().Verify(ck2, h.t->FmdSig()));
    BOOST_CHECK(!FmdTest(h.t->FmdDetectionKey(FMD_GAMMA), flag));

    BOOST_CHECK(h.t->FmdDetectionKey(0).empty());
    BOOST_CHECK(h.t->FmdDetectionKey(FMD_GAMMA + 1).empty());
}

BOOST_AUTO_TEST_SUITE_END()
