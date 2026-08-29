// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/transport.h>

#include <blsct/arith/blst/blst_scalar.h>
#include <logging.h>
#include <streams.h>
#include <util/time.h>

#include <atomic>
#include <cstring>

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
        // Reject trailing bytes: the envelope must consume the whole body. The
        // replay key (enc.MsgHash) does not cover framing/trailing data, so
        // accepting a suffix would be a malleability footgun.
        if (!ss.empty()) return false;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}
} // namespace

Transport::Transport(WorkerPool& pool, BroadcastFn broadcast, RelayFn relay, Options opts)
    : m_pool(pool), m_broadcast(std::move(broadcast)), m_relay(std::move(relay)),
      m_opts(opts),
      m_identity_priv(BlstScalar::Rand(/*exclude_zero=*/true)),
      m_identity_pub(m_identity_priv.GetPublicKey()),
      m_inbox_priv(BlstScalar::Rand(/*exclude_zero=*/true)),
      m_inbox_pub(m_inbox_priv.GetPublicKey())
{
    // Sign the initial prekey under the identity so the published bundle is
    // authenticated from the first message.
    m_prekey_sig = m_identity_priv.Sign(m_inbox_pub.GetVch());
    m_replay.setup_bytes(m_opts.replay_cache_bytes);
    m_relay_tokens = static_cast<double>(m_opts.relay_burst); // start with a full burst
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
    const int64_t ov = now_override.load(std::memory_order_relaxed);
    if (ov != 0) return ov;
    return GetTime<std::chrono::seconds>().count();
}

bool Transport::AllowRelay()
{
    const int64_t now = Now();
    LOCK(m_relay_limit_mutex);
    if (m_relay_last_refill == 0) m_relay_last_refill = now;
    const int64_t elapsed = now - m_relay_last_refill;
    if (elapsed > 0) {
        m_relay_tokens = std::min<double>(
            static_cast<double>(m_opts.relay_burst),
            m_relay_tokens + static_cast<double>(elapsed) * m_opts.relay_tokens_per_sec);
        m_relay_last_refill = now;
    }
    if (m_relay_tokens >= 1.0) {
        m_relay_tokens -= 1.0;
        return true;
    }
    return false;
}

void Transport::RegisterHandler(PayloadKind kind, MessageHandler handler)
{
    m_handlers[static_cast<uint8_t>(kind)] = std::move(handler);
}

void Transport::AddSessionKey(const blsct::PublicKey& pub, const blsct::PrivateKey& priv, int64_t expiry)
{
    const int64_t now = Now();
    LOCK(m_session_mutex);
    // Opportunistically drop expired keys so the trial-decrypt set stays small.
    std::erase_if(m_session_keys, [now](const auto& e) {
        return e.second.expiry != 0 && e.second.expiry <= now;
    });
    // Replace any existing entry for the same pubkey.
    const auto vch = pub.GetVch();
    std::erase_if(m_session_keys, [&vch](const auto& e) { return e.first.GetVch() == vch; });
    // Bound the trial-decrypt set: if full, evict the oldest key (front) so a
    // caller that opens many requests without dropping them cannot grow the
    // per-message decrypt cost without limit.
    while (m_session_keys.size() >= MAX_SESSION_KEYS) {
        m_session_keys.erase(m_session_keys.begin());
    }
    m_session_keys.emplace_back(pub, SessionKey{priv, expiry});
}

void Transport::DropSessionKey(const blsct::PublicKey& pub)
{
    const auto vch = pub.GetVch();
    LOCK(m_session_mutex);
    std::erase_if(m_session_keys, [&vch](const auto& e) { return e.first.GetVch() == vch; });
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
    // Distinguish a stale/clock-skewed timestamp from a genuinely bad-difficulty
    // stamp: an honest message can age past the tolerance window during
    // multi-hop propagation, and the relaying peer is not at fault for that.
    if (!CheckPoW(env.pow, m_opts.pow_bits)) return WireResult::RejectPoW;
    if (!CheckTimestamp(env.pow, Now())) return WireResult::RejectStale;

    // Single replay cache. Keyed by SHA256(kind || packet-hash): the packet
    // hash (MsgHash) does NOT cover the kind byte, so keying on it alone would
    // let an attacker pre-broadcast a kind-flipped copy that arrives first and
    // suppresses the genuine message as a "replay". Including kind gives each
    // (kind, ciphertext) its own slot while staying nonce-independent, so
    // re-grinding the PoW nonce still cannot bypass the replay cache (no relay
    // amplification). Also the relay loop-breaker: relayed at most once/node.
    HashWriter hw;
    hw << env.kind << env.enc.MsgHash();
    const uint256 msg_hash = hw.GetSHA256();
    {
        LOCK(m_replay_mutex);
        if (m_replay.contains(msg_hash, /*erase=*/false)) return WireResult::RejectReplay;
        m_replay.insert(msg_hash);
    }

    // App-agnostic flood: relay this new, valid message to every other peer,
    // whether or not we understand `kind` or can decrypt it. This is what lets
    // a future application propagate network-wide with no node upgrade. The
    // token bucket caps how fast this node will amplify, since a single ground
    // PoW is otherwise reusable to make us fan out to every peer. Over budget,
    // we skip the relay but still decrypt anything addressed to us below.
    if (m_relay && AllowRelay()) m_relay(from_peer, stem, env);

    // Enqueue the raw bytes for our own decryption on a worker; net thread done.
    Job job;
    job.kind = JOB_KIND_DECRYPT;
    job.peer = from_peer;
    job.len = static_cast<uint32_t>(body.size());
    std::memcpy(job.buf.data(), body.data(), body.size());
    if (!m_pool.Enqueue(job)) {
        // The worker ring is full. Do NOT leave this message recorded as seen:
        // otherwise a burst that fills the ring would permanently black-hole a
        // message addressed to us (every re-broadcast rejected as replay, never
        // decrypted). Erase it so a later re-broadcast gets another chance.
        LOCK(m_replay_mutex);
        m_replay.contains(msg_hash, /*erase=*/true);
        return WireResult::Dropped;
    }
    return WireResult::Enqueued;
}

void Transport::HandleJob(const Job& job)
{
    Envelope env;
    if (!ParseEnvelope({job.buf.data(), job.len}, env)) return;

    // The kind byte is bound as AEAD associated data, so decryption also
    // verifies the kind was not altered in flight.
    const uint8_t aad[1] = {env.kind};
    const std::span<const uint8_t> aad_span{aad, 1};

    // Try our inbox keys first (confidential, addressed to us): the current key
    // and any still-live grace-ring keys from a recent rotation. Snapshot the
    // privs under the lock, then run the heavy BLS decrypts outside it.
    RecipientKey recipient = RecipientKey::INBOX;
    std::vector<blsct::PrivateKey> inbox_privs;
    {
        LOCK(m_inbox_mutex);
        inbox_privs.reserve(1 + m_inbox_prev.size());
        inbox_privs.push_back(m_inbox_priv);
        for (const auto& p : m_inbox_prev) inbox_privs.push_back(p);
    }
    std::optional<std::vector<uint8_t>> plain;
    for (const auto& priv : inbox_privs) {
        plain = Decrypt(priv, env.enc, aad_span);
        if (plain) break;
    }
    if (!plain) {
        plain = Decrypt(BroadcastPrivKey(), env.enc, aad_span);
        if (plain) recipient = RecipientKey::BROADCAST;
    }
    if (!plain) {
        // Finally, any open per-request session keys (e.g. RFQ reply_keys). Take
        // a snapshot of the still-live privs under the lock, then decrypt outside
        // it — BLS decrypts are heavy and must not run while the mutex is held.
        std::vector<blsct::PrivateKey> session_privs;
        {
            const int64_t now = Now();
            LOCK(m_session_mutex);
            session_privs.reserve(m_session_keys.size());
            for (const auto& [pub, sk] : m_session_keys) {
                if (sk.expiry == 0 || sk.expiry > now) session_privs.push_back(sk.priv);
            }
        }
        for (const auto& priv : session_privs) {
            plain = Decrypt(priv, env.enc, aad_span);
            if (plain) {
                recipient = RecipientKey::SESSION;
                break;
            }
        }
    }
    if (!plain) {
        // MAC failure: not addressed to us and not a public announcement, or
        // corrupt. Drop silently — the common case for traffic we just relayed.
        return;
    }

    const auto kind = static_cast<PayloadKind>(env.kind);
    const MessageHandler& handler = m_handlers[env.kind];
    if (!handler) return;

    InboundMessage msg;
    msg.kind = kind;
    msg.from_peer = job.peer;
    msg.sender_session = env.enc.eph;
    msg.recipient = recipient;
    msg.body = std::move(*plain);
    handler(msg);
}

blsct::PublicKey Transport::IdentityPubKey() const
{
    LOCK(m_inbox_mutex);
    return m_identity_pub;
}

blsct::PublicKey Transport::InboxPubKey() const
{
    LOCK(m_inbox_mutex);
    return m_inbox_pub;
}

blsct::Signature Transport::PrekeySig() const
{
    LOCK(m_inbox_mutex);
    return m_prekey_sig;
}

std::vector<unsigned char> Transport::IdentityPrivBytes() const
{
    LOCK(m_inbox_mutex);
    return m_identity_priv.GetScalar().GetVch();
}

void Transport::SetIdentity(const blsct::PrivateKey& priv)
{
    LOCK(m_inbox_mutex);
    m_identity_priv = priv;
    m_identity_pub = priv.GetPublicKey();
    // Re-sign the current prekey under the new identity so the bundle stays
    // consistent.
    m_prekey_sig = m_identity_priv.Sign(m_inbox_pub.GetVch());
}

blsct::Signature Transport::SignWithIdentity(const uint256& digest) const
{
    LOCK(m_inbox_mutex);
    return m_identity_priv.Sign(digest);
}

void Transport::RotatePrekey()
{
    blsct::PrivateKey fresh(BlstScalar::Rand(/*exclude_zero=*/true));
    blsct::PublicKey fresh_pub(fresh.GetPublicKey());
    LOCK(m_inbox_mutex);
    // Retire the current prekey into the grace ring (newest first) so a message
    // encrypted to the prekey we just published still decrypts for a window.
    if (m_opts.prekey_grace_keys > 0) {
        m_inbox_prev.push_front(m_inbox_priv);
        while (m_inbox_prev.size() > m_opts.prekey_grace_keys) m_inbox_prev.pop_back();
    } else {
        m_inbox_prev.clear();
    }
    m_inbox_priv = fresh;
    m_inbox_pub = fresh_pub;
    m_prekey_sig = m_identity_priv.Sign(m_inbox_pub.GetVch());
    m_inbox_rotated_at = Now();
}

void Transport::MaybeRotatePrekey()
{
    if (m_opts.prekey_rotation_secs <= 0) return;
    {
        LOCK(m_inbox_mutex);
        // Baseline the rotation clock on the first tick rather than at
        // construction: Now() honours the test time override, which is set after
        // the Transport is built, and in production this merely defers the first
        // rotation by one scheduler tick.
        if (m_inbox_rotated_at == 0) {
            m_inbox_rotated_at = Now();
            return;
        }
        if (Now() - m_inbox_rotated_at < m_opts.prekey_rotation_secs) return;
    }
    RotatePrekey();
}

std::pair<blsct::PublicKey, blsct::Signature> Transport::SignEphemeral(const uint256& digest) const
{
    blsct::PrivateKey k(BlstScalar::Rand(/*exclude_zero=*/true));
    return {k.GetPublicKey(), k.Sign(digest)};
}

void Transport::Send(const blsct::PublicKey& recipient, PayloadKind kind,
                     std::vector<uint8_t> body, bool stem)
{
    Envelope env;
    env.kind = static_cast<uint8_t>(kind);
    // Authenticate the (cleartext) kind byte under the AEAD so it cannot be
    // flipped in flight to route the same ciphertext to a different handler.
    const uint8_t aad[1] = {env.kind};
    env.enc = Encrypt(recipient, std::span<const uint8_t>{body.data(), body.size()},
                      std::span<const uint8_t>{aad, 1});

    // PoW is mandatory on every message — it is the bus's universal admission
    // gate, applied regardless of `kind`.
    env.pow.version = 1;
    env.pow.timestamp = Now();
    env.pow.kind = env.kind;
    env.pow.session_eph = env.enc.eph;
    env.pow.payload_hash = env.enc.MsgHash();
    env.pow.nonce = 0;
    // Grind returns 0 if it was interrupted (shutdown) before finding a valid
    // nonce. Do NOT broadcast in that case: env.pow.nonce is wherever the loop
    // stopped, so CheckPoW fails on it -- every peer would drop it, and on the
    // stem path it would waste the epoch's single relay on an envelope that
    // cannot survive. Abandon the send instead.
    if (Grind(env.pow, m_opts.pow_bits, /*max_iters=*/0, &m_interrupt) == 0) {
        LogPrint(BCLog::NET, "p2pmsg: send abandoned, PoW grind interrupted (shutdown)\n");
        return;
    }

    m_broadcast(stem, env);
    (void)&SerializeEnvelope; // reserved for direct-send paths in later phases
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
