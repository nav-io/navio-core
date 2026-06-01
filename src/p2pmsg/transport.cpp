// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/transport.h>

#include <blsct/arith/mcl/mcl_scalar.h>
#include <logging.h>
#include <streams.h>
#include <util/time.h>

#include <atomic>

namespace p2pmsg {

namespace {
//! Reserved Job::kind used to route every p2pmsg decrypt through one handler.
constexpr uint8_t JOB_KIND_DECRYPT = 200;

//! Serialize an envelope to a byte vector.
std::vector<uint8_t> SerializeEnvelope(const Envelope& env)
{
    DataStream ss;
    ss << env;
    auto bytes = MakeUCharSpan(ss);
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

//! Try to parse an envelope from raw bytes. Returns false on malformed input.
bool ParseEnvelope(std::span<const uint8_t> body, Envelope& out)
{
    try {
        DataStream ss{MakeByteSpan(body)};
        ss >> out;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}
} // namespace

Transport::Transport(WorkerPool& pool, SendFn send, BroadcastFn broadcast, RelayFn relay, Options opts)
    : m_pool(pool), m_send(std::move(send)), m_broadcast(std::move(broadcast)), m_relay(std::move(relay)),
      m_opts(opts),
      m_inbox_priv(MclScalar::Rand(/*exclude_zero=*/true)),
      m_inbox_pub(m_inbox_priv.GetPublicKey())
{
    m_replay.setup_bytes(m_opts.replay_cache_bytes);
    // All decrypt work funnels through one worker handler keyed by JOB_KIND_DECRYPT.
    // Replay was already recorded on the net thread in OnWire(); HandleJob does
    // not touch the replay cache, so it holds no lock here.
    m_pool.RegisterHandler(JOB_KIND_DECRYPT, [this](const Job& job) {
        HandleJob(job);
    });

    // Built-in PING accounting so the echo path is observable without a feature
    // module registered. A feature may still override PING later if desired.
    RegisterHandler(PayloadKind::PING, [this](const InboundMessage&) {
        m_pings_received.fetch_add(1, std::memory_order_relaxed);
    });
}

int64_t Transport::Now() const
{
    if (now_override != 0) return now_override;
    return GetTime<std::chrono::seconds>().count();
}

void Transport::RegisterHandler(PayloadKind kind, MessageHandler handler)
{
    m_handlers[static_cast<uint8_t>(kind)] = std::move(handler);
}

Transport::WireResult Transport::OnWire(int64_t from_peer, bool stem, std::span<const uint8_t> body)
{
    if (body.size() > MAX_JOB_BYTES) return WireResult::RejectInvalid;

    Envelope env;
    if (!ParseEnvelope(body, env)) return WireResult::RejectInvalid;

    // Mandatory PoW gate — the universal admission check that makes kind-blind
    // relay safe. The header binds the ciphertext via payload_hash, so a valid
    // PoW vouches for the body before we relay it or spend a worker decrypting.
    if (env.pow.kind != env.kind) return WireResult::RejectPoW;
    if (env.pow.payload_hash != env.enc.MsgHash()) return WireResult::RejectPoW;
    if (!CheckStamp(env.pow, m_opts.pow_bits, Now())) return WireResult::RejectPoW;

    // Single replay cache, keyed by the encrypted-packet hash. Also the relay
    // loop-breaker: a message is relayed at most once per node.
    const uint256 msg_hash = env.enc.MsgHash();
    {
        LOCK(m_replay_mutex);
        if (m_replay.contains(msg_hash, /*erase=*/false)) return WireResult::RejectReplay;
        m_replay.insert(msg_hash);
    }

    // App-agnostic flood: relay this new, valid message to every other peer,
    // whether or not we understand `kind` or can decrypt it. This is what lets
    // a future application propagate network-wide with no node upgrade.
    if (m_relay) m_relay(from_peer, stem, env);

    // Enqueue the raw bytes for our own decryption on a worker; net thread done.
    Job job;
    job.kind = JOB_KIND_DECRYPT;
    job.peer = from_peer;
    job.len = static_cast<uint32_t>(body.size());
    std::memcpy(job.buf.data(), body.data(), body.size());
    if (!m_pool.Enqueue(job)) return WireResult::Dropped;
    return WireResult::Enqueued;
}

void Transport::HandleJob(const Job& job)
{
    Envelope env;
    if (!ParseEnvelope({job.buf.data(), job.len}, env)) return;

    auto plain = Decrypt(m_inbox_priv, env.enc);
    if (!plain) {
        // MAC failure: not addressed to us, or corrupt. Drop silently — this is
        // the common case for broadcast traffic we are merely relaying.
        return;
    }

    const auto kind = static_cast<PayloadKind>(env.kind);
    const MessageHandler& handler = m_handlers[env.kind];
    if (!handler) return;

    InboundMessage msg;
    msg.kind = kind;
    msg.from_peer = job.peer;
    msg.sender_session = env.enc.eph;
    msg.body = std::move(*plain);
    handler(msg);
}

void Transport::Send(const blsct::PublicKey& recipient, PayloadKind kind,
                     std::vector<uint8_t> body, bool stem)
{
    Envelope env;
    env.kind = static_cast<uint8_t>(kind);
    env.enc = Encrypt(recipient, body);

    // PoW is mandatory on every message — it is the bus's universal admission
    // gate, applied regardless of `kind`.
    env.pow.version = 1;
    env.pow.timestamp = Now();
    env.pow.kind = env.kind;
    env.pow.session_eph = env.enc.eph;
    env.pow.payload_hash = env.enc.MsgHash();
    env.pow.nonce = 0;
    Grind(env.pow, m_opts.pow_bits);

    m_broadcast(stem, env);
    (void)SerializeEnvelope; // reserved for direct-send paths in later phases
}

namespace {
//! Plain atomic pointer; lifetime owned by NodeContext. Net thread only reads.
std::atomic<Transport*> g_active_transport{nullptr};
} // namespace

void SetActiveTransport(Transport* transport)
{
    g_active_transport.store(transport, std::memory_order_release);
}

Transport* GetActiveTransport()
{
    return g_active_transport.load(std::memory_order_acquire);
}

} // namespace p2pmsg
