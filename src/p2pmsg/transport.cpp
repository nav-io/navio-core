// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/transport.h>

#include <blsct/arith/blst/blst_scalar.h>
#include <logging.h>
#include <streams.h>
#include <util/time.h>

#include <algorithm>
#include <atomic>
#include <cstring>

namespace p2pmsg {

namespace {
//! Reserved Job::kind used to route every p2pmsg decrypt through one handler.
constexpr uint8_t JOB_KIND_DECRYPT = 200;

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
    m_fmd_key = FmdSecretKey::Random();
    m_fmd_sig = m_identity_priv.Sign(m_fmd_key.GetClueKey().ToBytes());
    m_replay.setup_bytes(m_opts.replay_cache_bytes);
    m_fluff_relayed.setup_bytes(m_opts.replay_cache_bytes);
    m_sent.setup_bytes(m_opts.replay_cache_bytes / 4);
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

bool Transport::AddSessionKey(const blsct::PublicKey& pub, const blsct::PrivateKey& priv, int64_t expiry, SessionPurpose purpose)
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
    // Per-purpose bounds: a chat app minting one USER_REPLY key per
    // conversation must not evict in-flight INTERNAL (RFQ/pull) keys, and a
    // burst of internal requests must not silently kill live minted keys.
    // USER_REPLY refuses when full (the RPC surfaces the error); INTERNAL
    // keeps the old evict-own-oldest behavior.
    const auto count_purpose = [&](SessionPurpose p) {
        return std::count_if(m_session_keys.begin(), m_session_keys.end(),
                             [p](const auto& e) { return e.second.purpose == p; });
    };
    if (purpose == SessionPurpose::USER_REPLY) {
        if (static_cast<size_t>(count_purpose(SessionPurpose::USER_REPLY)) >= MAX_USER_REPLY_KEYS) return false;
    } else {
        while (static_cast<size_t>(count_purpose(SessionPurpose::INTERNAL)) >= MAX_SESSION_KEYS - MAX_USER_REPLY_KEYS) {
            auto it = std::find_if(m_session_keys.begin(), m_session_keys.end(),
                                   [](const auto& e) { return e.second.purpose == SessionPurpose::INTERNAL; });
            if (it == m_session_keys.end()) break;
            m_session_keys.erase(it);
        }
    }
    m_session_keys.emplace_back(pub, SessionKey{priv, expiry, purpose});
    return true;
}

void Transport::DropSessionKey(const blsct::PublicKey& pub)
{
    const auto vch = pub.GetVch();
    LOCK(m_session_mutex);
    std::erase_if(m_session_keys, [&vch](const auto& e) { return e.first.GetVch() == vch; });
}

bool Transport::HasSessionKey(const blsct::PublicKey& pub) const
{
    const auto vch = pub.GetVch();
    const int64_t now = Now();
    LOCK(m_session_mutex);
    return std::any_of(m_session_keys.begin(), m_session_keys.end(), [&](const auto& e) {
        return e.first.GetVch() == vch && (e.second.expiry == 0 || e.second.expiry > now);
    });
}

Transport::WireResult Transport::OnWire(int64_t from_peer, bool stem, bool wire_stem, std::span<const uint8_t> body)
{
    if (body.size() > MAX_JOB_BYTES) return WireResult::RejectInvalid;

    Envelope env;
    if (!ParseEnvelope(body, env)) return WireResult::RejectInvalid;

    // Mandatory PoW gate — the universal admission check that makes kind-blind
    // relay safe. The header binds the ciphertext AND the flag via payload_hash,
    // so a valid PoW vouches for both before we relay or spend a worker
    // decrypting.
    // Envelope v2 only. v1 headers bound the ciphertext alone, so accepting
    // both would let a v1 stamp be replayed as a v2 envelope with an attacker's
    // flag attached. The hashes differ even for an empty flag, so rejecting the
    // version outright is the clean separation.
    if (env.pow.version != POW_VERSION_CURRENT) return WireResult::RejectInvalid;
    if (env.flag.size() > MAX_FLAG_BYTES) return WireResult::RejectInvalid;
    if (env.pow.kind != env.kind) return WireResult::RejectPoW;
    if (env.pow.payload_hash != env.ExpectedPayloadHash()) return WireResult::RejectPoW;
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
    hw << env.kind << env.pow.payload_hash;
    const uint256 msg_hash = hw.GetSHA256();
    // Loop-tolerant relay policy. The stem successor graph has no loop
    // freedom (with few peers A->B->A is common), and a plain seen-once
    // replay cache makes a stem loop fatal: every node in the loop consumes
    // its single relay on the stem pass, so the message dies inside the loop
    // and never reaches its recipient — this transport has no Dandelion
    // embargo timer to save it. Instead each node may relay a message at
    // most TWICE: once in stem mode (first arrival) and once as fluff (first
    // duplicate). A duplicate proves the stem looped; the fluff copy floods
    // outward, and a node that only ever stem-relayed still forwards the
    // fluff when it arrives, so the flood escapes the loop. Amplification is
    // bounded at one extra flood per node per message.
    bool fluff_rescue = false;
    bool self_echo_deliver = false;
    {
        LOCK(m_replay_mutex);
        const bool seen = m_replay.contains(msg_hash, /*erase=*/false);
        const bool fluffed = m_fluff_relayed.contains(msg_hash, /*erase=*/false);
        const bool sent_by_us = m_sent.contains(msg_hash, /*erase=*/false);
        if (!seen) {
            m_replay.insert(msg_hash);
            if (sent_by_us) {
                // The echo of our OWN message. Relay it exactly like any
                // other node's first duplicate (one metered fluff below) so
                // the originator is indistinguishable on the wire -- but
                // still decrypt/dispatch it once, so a message sent to our
                // own inbox is delivered locally.
                if (!fluffed) {
                    m_fluff_relayed.insert(msg_hash);
                    fluff_rescue = true;
                    self_echo_deliver = true;
                }
            } else if (!stem) {
                m_fluff_relayed.insert(msg_hash);
            }
        } else if (!fluffed) {
            m_fluff_relayed.insert(msg_hash);
            fluff_rescue = true;
        } else {
            return WireResult::RejectReplay;
        }
    }
    if (fluff_rescue) {
        // Relay in fluff mode through the same AllowRelay() token bucket as
        // every other relay: the duplicate reuses the original PoW, so an
        // unmetered second fan-out would let one grind double network-wide
        // relay for free. A rescue skipped under pressure just leaves the
        // message where a plain replay drop would have -- the bucket bounds
        // aggregate rate either way.
        // wire_stem=false: a duplicate is one the origin already holds, so
        // there is nothing to hand back to it even if we turn out to be a
        // dead end.
        if (m_relay && AllowRelay()) m_relay(from_peer, /*stem=*/false, /*wire_stem=*/false, env);
        // A true duplicate was already decrypted on first arrival; our own
        // echo has not been -- fall through to the decrypt enqueue for it.
        if (!self_echo_deliver) return WireResult::Dropped;
        goto enqueue_decrypt; // rescue already relayed; the normal relay below must NOT also fire
    }

    // App-agnostic flood: relay this new, valid message to every other peer,
    // whether or not we understand `kind` or can decrypt it. This is what lets
    // a future application propagate network-wide with no node upgrade. The
    // token bucket caps how fast this node will amplify, since a single ground
    // PoW is otherwise reusable to make us fan out to every peer. Over budget,
    // we skip the relay but still decrypt anything addressed to us below.
    if (m_relay && AllowRelay()) m_relay(from_peer, stem, wire_stem, env);

enqueue_decrypt:

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

void Transport::SetArchiveSink(ArchiveFn fn)
{
    LOCK(m_archive_mutex);
    m_has_archive.store(static_cast<bool>(fn), std::memory_order_release);
    m_archive = std::move(fn);
}

void Transport::HandleJob(const Job& job)
{
    Envelope env;
    if (!ParseEnvelope({job.buf.data(), job.len}, env)) return;

    // Archive the flagged envelope before doing anything with its contents. It
    // is retained whether or not WE can decrypt it -- the whole point is to
    // hold ciphertext for somebody else. This runs here, on a worker, rather
    // than in OnWire: the net thread must never block on a disk write. A
    // message dropped because the worker ring was full is therefore not
    // archived, which is correct -- it was not relayed either.
    if (!env.flag.empty() && m_has_archive.load(std::memory_order_acquire)) {
        LOCK(m_archive_mutex);
        if (m_archive) {
            // Both spans built explicitly: libc++ 14 (the Ubuntu 22.04 CI
            // compiler) ships no std::span range constructor, so env.flag,
            // being a std::vector, does not convert on its own.
            m_archive(Now(), env.kind,
                      std::span<const uint8_t>{env.flag.data(), env.flag.size()},
                      std::span<const uint8_t>{job.buf.data(), job.len});
        }
    }

    // The kind byte is bound as AEAD associated data, so decryption also
    // verifies the kind was not altered in flight.
    const uint8_t aad[1] = {env.kind};
    const std::span<const uint8_t> aad_span{aad, 1};

    // Try our inbox keys first (confidential, addressed to us): the current key
    // and any still-live grace-ring keys from a recent rotation. Snapshot the
    // privs under the lock, then run the heavy BLS decrypts outside it.
    RecipientKey recipient = RecipientKey::INBOX;
    blsct::PublicKey matched_session;
    bool matched_user_reply = false;
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
        struct SessionCandidate {
            blsct::PublicKey pub;
            blsct::PrivateKey priv;
            SessionPurpose purpose;
        };
        std::vector<SessionCandidate> session_candidates;
        {
            const int64_t now = Now();
            LOCK(m_session_mutex);
            session_candidates.reserve(m_session_keys.size());
            for (const auto& [pub, sk] : m_session_keys) {
                if (sk.expiry == 0 || sk.expiry > now) session_candidates.push_back({pub, sk.priv, sk.purpose});
            }
        }
        for (const auto& cand : session_candidates) {
            plain = Decrypt(cand.priv, env.enc, aad_span);
            if (plain) {
                recipient = RecipientKey::SESSION;
                matched_session = cand.pub;
                matched_user_reply = (cand.purpose == SessionPurpose::USER_REPLY);
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
    msg.recipient_session = matched_session;
    msg.recipient_user_reply = matched_user_reply;
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
    // Re-sign the current prekey AND the clue key under the new identity so the
    // whole published bundle stays consistent.
    m_prekey_sig = m_identity_priv.Sign(m_inbox_pub.GetVch());
    m_fmd_sig = m_identity_priv.Sign(m_fmd_key.GetClueKey().ToBytes());
}

std::vector<uint8_t> Transport::FmdClueKeyBytes() const
{
    LOCK(m_inbox_mutex);
    return m_fmd_key.GetClueKey().ToBytes();
}

blsct::Signature Transport::FmdSig() const
{
    LOCK(m_inbox_mutex);
    return m_fmd_sig;
}

std::vector<uint8_t> Transport::FmdDetectionKey(size_t precision) const
{
    LOCK(m_inbox_mutex);
    return m_fmd_key.Extract(precision);
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
    // Rotate the FMD key with it. Detection keys handed out under the previous
    // clue key stop matching, which is the point: a detection key is otherwise
    // valid forever. Retired FMD keys are NOT kept in a grace ring -- a flag is
    // only a retrieval hint, so an unmatched flag from a stale sender costs the
    // message nothing on the live bus, it just will not be archivable.
    m_fmd_key = FmdSecretKey::Random();
    m_fmd_sig = m_identity_priv.Sign(m_fmd_key.GetClueKey().ToBytes());
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

uint64_t Transport::TakeSendTicket(const StreamKey& key)
{
    LOCK(m_send_order_mutex);
    SendStream& s = m_send_streams[key];
    ++s.holders;
    m_send_tickets_issued.fetch_add(1, std::memory_order_release);
    return s.next_ticket++;
}

bool Transport::AwaitSendTurn(const StreamKey& key, uint64_t ticket)
{
    WAIT_LOCK(m_send_order_mutex, lock);
    m_send_order_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_send_order_mutex) {
        AssertLockHeld(m_send_order_mutex);
        if (m_interrupt.load(std::memory_order_relaxed)) return true;
        const auto it = m_send_streams.find(key);
        // `>=`, not `==`: a holder that abandoned its send out of turn moves
        // now_serving past its own ticket, and an earlier ticket must then run
        // immediately rather than wait for a turn that already went by.
        return it == m_send_streams.end() || it->second.now_serving >= ticket;
    });
    return !m_interrupt.load(std::memory_order_relaxed);
}

void Transport::ReleaseSendTurn(const StreamKey& key, uint64_t ticket)
{
    {
        LOCK(m_send_order_mutex);
        const auto it = m_send_streams.find(key);
        if (it == m_send_streams.end()) return;
        SendStream& s = it->second;
        if (s.now_serving <= ticket) s.now_serving = ticket + 1;
        // Last holder out drops the stream, so the map only ever holds streams
        // with a send in flight.
        if (--s.holders == 0) m_send_streams.erase(it);
    }
    m_send_order_cv.notify_all();
}

bool Transport::IsValidRecipient(const blsct::PublicKey& recipient)
{
    const BlstG1Point rp = recipient.GetG1Point();
    return !rp.IsZero() && rp.IsValid();
}

bool Transport::Send(const blsct::PublicKey& recipient, PayloadKind kind,
                     std::vector<uint8_t> body, bool stem,
                     std::vector<uint8_t> flag)
{
    // Guard the OUTBOUND recipient key (mirrors Decrypt's inbound eph guard):
    // identity/invalid forces the ECDH secret to a public constant, key+nonce
    // reuse under ZERO_NONCE. Reply keys come from the network, so a peer can
    // reach this -- return false, never throw (a throw on the candserve thread
    // reaches TraceThread and terminates the node).
    if (!IsValidRecipient(recipient)) {
        LogPrint(BCLog::NET, "p2pmsg: refusing to send to identity/invalid recipient key\n");
        return false;
    }
    if (flag.size() > MAX_FLAG_BYTES) {
        LogPrint(BCLog::NET, "p2pmsg: refusing to send, detection flag too large\n");
        return false;
    }

    // Claim this stream's place in the emission order NOW, before the heavy
    // encrypt+grind, so the wire order is the order the application called us
    // in rather than the order the grinds happened to land. See SendStream.
    // After the cheap argument checks above: a request we are going to reject
    // should not take a turn that a valid one is waiting for.
    const StreamKey stream{static_cast<uint8_t>(kind), recipient.GetVch()};
    const uint64_t ticket = TakeSendTicket(stream);
    struct TurnGuard {
        Transport& self;
        const StreamKey& key;
        uint64_t ticket;
        ~TurnGuard() { self.ReleaseSendTurn(key, ticket); }
    } turn_guard{*this, stream, ticket};

    Envelope env;
    env.kind = static_cast<uint8_t>(kind);
    env.flag = std::move(flag);
    // Authenticate the (cleartext) kind byte under the AEAD so it cannot be
    // flipped in flight to route the same ciphertext to a different handler.
    const uint8_t aad[1] = {env.kind};
    env.enc = Encrypt(recipient, std::span<const uint8_t>{body.data(), body.size()},
                      std::span<const uint8_t>{aad, 1});

    // PoW is mandatory on every message — it is the bus's universal admission
    // gate, applied regardless of `kind`.
    env.pow.version = POW_VERSION_CURRENT;
    env.pow.timestamp = Now();
    env.pow.kind = env.kind;
    env.pow.session_eph = env.enc.eph;
    // v2: commits to the flag as well, so the work cannot be reused with a
    // different (or stripped) flag.
    env.pow.payload_hash = env.ExpectedPayloadHash();
    env.pow.nonce = 0;
    // Grind returns 0 if it was interrupted (shutdown) before finding a valid
    // nonce. Do NOT broadcast in that case: env.pow.nonce is wherever the loop
    // stopped, so CheckPoW fails on it -- every peer would drop it, and on the
    // stem path it would waste the epoch's single relay on an envelope that
    // cannot survive. Abandon the send instead.
    if (Grind(env.pow, m_opts.pow_bits, /*max_iters=*/0, &m_interrupt) == 0) {
        LogPrint(BCLog::NET, "p2pmsg: send abandoned, PoW grind interrupted (shutdown)\n");
        return false;
    }

    // Grind done; now wait for the earlier messages on this stream to go out.
    // A predecessor is at most one grind away, and shutdown releases everyone.
    if (!AwaitSendTurn(stream, ticket)) {
        LogPrint(BCLog::NET, "p2pmsg: send abandoned, shutting down while waiting to broadcast\n");
        return false;
    }

    // Record our own message in the replay/fluff caches BEFORE broadcasting:
    // otherwise, when the network echoes it back, the originator treats it as
    // brand new (relaying again) while every other node replay-drops or
    // single-rescues it -- an observable asymmetry that identifies the
    // originator across two probes, contradicting the stem's purpose.
    {
        HashWriter hw;
        hw << env.kind << env.pow.payload_hash;
        const uint256 msg_hash = hw.GetSHA256();
        LOCK(m_replay_mutex);
        m_sent.insert(msg_hash);
    }
    m_broadcast(stem, env);
    return true;
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
