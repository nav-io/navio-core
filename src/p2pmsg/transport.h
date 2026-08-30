// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_TRANSPORT_H
#define BITCOIN_P2PMSG_TRANSPORT_H

#include <p2pmsg/crypto.h>
#include <p2pmsg/pow.h>
#include <p2pmsg/worker_pool.h>

#include <cuckoocache.h>
#include <serialize.h>
#include <sync.h>
#include <uint256.h>
#include <util/hasher.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <vector>

namespace p2pmsg {

//! Whether the p2p messaging subsystem is enabled by default. The feature set
//! (aggregation cover traffic, RFQ swaps, standing orders) is implemented and
//! integration-tested end-to-end on a live chain, so it is on by default;
//! disable with -p2pmsg=0.
static constexpr bool DEFAULT_P2PMSG_ENABLE{true};

//! Application identifier carried (opaque) by every message. p2pmsg is an
//! APP-AGNOSTIC encrypted broadcast bus: nodes relay any well-formed message to
//! their peers regardless of whether they understand or can decrypt this `kind`.
//! A new application simply claims a new byte and ships a handler in a wallet or
//! daemon; existing nodes propagate it network-wide with no upgrade. The values
//! below are the kinds this build's own apps handle locally; the wire field is a
//! plain u8 and unknown kinds are still relayed.
enum class PayloadKind : uint8_t {
    PING = 0,
    PONG = 1,
    AGG_ANN = 2,
    CANDIDATE_TX = 3,
    RFQ_REQ = 4,
    RFQ_QUOTE = 5,
    ORDER_ANN = 6,
    // 7..255 reserved for future applications. The relay layer never inspects
    // this value beyond keying handler dispatch on the receiving node.
};

//! The wire envelope for a `p2pmsg`/`dp2pmsg` net message:
//!   u8 kind || PoWHeader || EciesPacket
//! PoW is MANDATORY on every message: it is the universal admission gate that
//! makes kind-blind relay safe (no free amplification). The header's
//! payload_hash binds the ciphertext, so the cheap net-thread PoW check vouches
//! for the body before any worker decrypts or any peer relays it.
struct Envelope {
    uint8_t kind{0};
    PoWHeader pow;
    EciesPacket enc;

    SERIALIZE_METHODS(Envelope, obj)
    {
        READWRITE(obj.kind, obj.pow, obj.enc);
    }
};

//! Broadcasts a fresh envelope to the stem successor (Dandelion) or, if no stem
//! route exists, to all relay peers.
using BroadcastFn = std::function<void(bool stem, const Envelope&)>;
//! Relay an already-received envelope to all peers EXCEPT its origin, so it
//! floods the network. Kind-blind: called for every new valid message whether
//! or not this node understands or can decrypt it.
using RelayFn = std::function<void(int64_t origin_peer, bool stem, const Envelope&)>;

//! Decrypted, authenticated inbound message handed to a feature module.
//! Which local key class decrypted an inbound message. Handlers use this to
//! enforce delivery semantics: e.g. a CANDIDATE_TX is only accepted when it
//! was encrypted 1:1 to one of our registered pull session keys — a candidate
//! readable under the well-known broadcast key is public, and public cover
//! candidates can be subtracted back out of an aggregate by any bus observer.
enum class RecipientKey : uint8_t {
    INBOX,     //!< our stable node inbox key
    BROADCAST, //!< the well-known broadcast key (anyone can read)
    SESSION,   //!< a per-request session key registered via AddSessionKey
};

struct InboundMessage {
    PayloadKind kind;
    int64_t from_peer;
    blsct::PublicKey sender_session; //!< the envelope's ephemeral pubkey
    RecipientKey recipient{RecipientKey::INBOX}; //!< which local key decrypted it
    std::vector<uint8_t> body;       //!< decrypted terminal payload
};
using MessageHandler = std::function<void(const InboundMessage&)>;

/**
 * Owns the node's inbound session key, the worker pool feeding heavy crypto,
 * the replay cache, and the per-kind feature handlers. The net thread calls
 * OnWire() which does only cheap checks + enqueue; decryption and dispatch run
 * on the worker pool.
 */
class Transport
{
public:
    struct Options {
        uint32_t pow_bits{DEFAULT_POW_BITS};
        size_t replay_cache_bytes{1 << 20}; // 1 MiB
        //! Relay rate limit (token bucket). PoW gates per-message cost but is
        //! reusable across all peers, so a sender that grinds continuously could
        //! otherwise make this node fan every message out to all peers without
        //! bound. Cap the messages this node relays per second (sustained) with a
        //! burst allowance. Exceeding the budget drops the *relay* only; we still
        //! decrypt and handle messages addressed to us.
        uint32_t relay_tokens_per_sec{200};
        uint32_t relay_burst{400};
        //! Encryption-prekey rotation. The node has a stable IDENTITY key (its
        //! address, which signs prekeys) and a rotating PREKEY that peers
        //! actually encrypt confidential messages to. Rotating the prekey bounds
        //! two things without disturbing reachability: linkage of confidential
        //! replies resets each epoch, and an in-memory prekey extraction exposes
        //! at most one epoch (plus the grace ring) of past traffic rather than
        //! the whole run. `prekey_grace_keys` previous prekeys are retained for
        //! trial-decryption so a message encrypted to the prekey we published
        //! just before a rotation still decrypts.
        //!
        //! Rotation is MANUAL by default (`prekey_rotation_secs == 0`): the inbox
        //! prekey is a contact address, and rotating it on a timer would silently
        //! break senders who cached it beyond the grace window. A user can force a
        //! privacy reset with the `rotatep2pmsginbox` RPC, or opt into periodic
        //! rotation by setting `prekey_rotation_secs > 0`.
        int64_t prekey_rotation_secs{0};
        size_t prekey_grace_keys{1};
    };

    //! Hard cap on simultaneously-registered session keys. Each open key is
    //! trial-decrypted against every inbound message that misses the inbox and
    //! broadcast keys (O(keys) heavy BLS ops per message), so the set must stay
    //! bounded even if a caller opens many requests without dropping them.
    static constexpr size_t MAX_SESSION_KEYS = 256;

    Transport(WorkerPool& pool, BroadcastFn broadcast, RelayFn relay, Options opts);
    Transport(WorkerPool& pool, BroadcastFn broadcast, RelayFn relay)
        : Transport(pool, std::move(broadcast), std::move(relay), Options{}) {}

    //! The node's stable IDENTITY key: its p2pmsg address. Signs the rotating
    //! prekey so a sender can verify a fetched prekey belongs to this identity.
    //! Ephemeral per run by default; persisted across runs when the operator
    //! injects a saved key via SetIdentity (opt-in, see -p2pmsgpersistidentity).
    blsct::PublicKey IdentityPubKey() const EXCLUSIVE_LOCKS_REQUIRED(!m_inbox_mutex);

    //! The current inbox PREKEY: peers encrypt confidential messages to this.
    //! Returns a copy because the prekey rotates, so a caller must re-read it
    //! rather than cache a reference.
    blsct::PublicKey InboxPubKey() const EXCLUSIVE_LOCKS_REQUIRED(!m_inbox_mutex);

    //! The identity's signature over the current prekey (over prekey.GetVch()).
    //! Published alongside IdentityPubKey()/InboxPubKey() as a prekey bundle so a
    //! sender can authenticate the prekey before encrypting to it.
    blsct::Signature PrekeySig() const EXCLUSIVE_LOCKS_REQUIRED(!m_inbox_mutex);

    //! Replace the identity keypair (e.g. with a persisted one loaded at
    //! startup) and re-sign the current prekey under it. Call before the node is
    //! live. Safe to call from any thread.
    void SetIdentity(const blsct::PrivateKey& priv) EXCLUSIVE_LOCKS_REQUIRED(!m_inbox_mutex);

    //! Export the raw identity private scalar (for persistence). Empty span-safe;
    //! the caller must treat the bytes as secret.
    std::vector<unsigned char> IdentityPrivBytes() const EXCLUSIVE_LOCKS_REQUIRED(!m_inbox_mutex);

    //! Rotate the inbox prekey now: the current prekey priv moves into the grace
    //! ring (trimmed to Options::prekey_grace_keys), a fresh prekey becomes
    //! current, and it is re-signed under the identity. Safe from any thread.
    void RotatePrekey() EXCLUSIVE_LOCKS_REQUIRED(!m_inbox_mutex);

    //! Rotate iff at least Options::prekey_rotation_secs have elapsed since the
    //! last rotation (no-op when periodic rotation is disabled, the default).
    void MaybeRotatePrekey() EXCLUSIVE_LOCKS_REQUIRED(!m_inbox_mutex);

    //! Sign a 32-byte digest under this node's stable identity key. Prefer
    //! SignEphemeral for anything that goes on the wire; identity signatures link
    //! the signature to this node.
    blsct::Signature SignWithIdentity(const uint256& digest) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_inbox_mutex);

    //! Sign `digest` under a FRESH, single-use keypair and return the matching
    //! pubkey to publish as the quote's `session_eph`. A self-signed quote only
    //! needs integrity, not identity — signing every quote/order with the stable
    //! inbox key instead makes all of a node's RFQ activity linkable to one
    //! pubkey (and, via getp2pmsginfo, to the node). A per-quote key gives the
    //! same tamper-resistance with no cross-quote linkage. Prefer this over
    //! SignWithIdentity for anything that goes on the wire.
    std::pair<blsct::PublicKey, blsct::Signature> SignEphemeral(const uint256& digest) const;

    //! Register a per-request session keypair so inbound messages encrypted to
    //! `pub` (e.g. an RFQ taker's fresh `reply_key`) are decrypted alongside the
    //! node inbox key. `expiry` is a unix-seconds bound past which the key is
    //! pruned (0 = no expiry; caller must DropSessionKey explicitly). Cheap; safe
    //! to call from any thread. Trial-decrypt cost is O(open session keys), so
    //! callers should drop keys once their request window closes.
    void AddSessionKey(const blsct::PublicKey& pub, const blsct::PrivateKey& priv,
                       int64_t expiry) EXCLUSIVE_LOCKS_REQUIRED(!m_session_mutex);

    //! Forget a previously registered session key. No-op if absent.
    void DropSessionKey(const blsct::PublicKey& pub)
        EXCLUSIVE_LOCKS_REQUIRED(!m_session_mutex);

    //! Register the handler for an application kind. Call before the net is live.
    void RegisterHandler(PayloadKind kind, MessageHandler handler);

    //! Net-thread entrypoint. `stem` = arrived as dp2pmsg. Parses the envelope,
    //! verifies the mandatory PoW + timestamp, checks the replay cache. If the
    //! message is new and valid it is RELAYED to all other peers (kind-blind, so
    //! the bus carries apps this node does not implement) and a decrypt job is
    //! enqueued for our own handlers. Returns the disposition.
    enum class WireResult { Enqueued, RejectInvalid, RejectPoW, RejectStale, RejectReplay, Dropped };
    WireResult OnWire(int64_t from_peer, bool stem, std::span<const uint8_t> body)
        EXCLUSIVE_LOCKS_REQUIRED(!m_replay_mutex, !m_relay_limit_mutex);

    //! Build + encrypt + PoW-stamp + broadcast an outbound message to
    //! `recipient`'s session key. PoW is always applied. Heavy; call off the net
    //! thread.
    void Send(const blsct::PublicKey& recipient, PayloadKind kind,
              std::vector<uint8_t> body, bool stem);

    //! Total PING payloads decrypted+dispatched to us. Debug/observability.
    uint64_t PingsReceived() const { return m_pings_received.load(std::memory_order_relaxed); }

    //! Test hook: if non-zero, used as "now". Atomic because Now() is read from
    //! both the net thread (OnWire) and worker threads (HandleJob).
    std::atomic<int64_t> now_override{0};

private:
    //! Decrypt + dispatch one enqueued job. Runs on a worker thread; touches no
    //! shared state guarded by m_replay_mutex.
    void HandleJob(const Job& job)
        EXCLUSIVE_LOCKS_REQUIRED(!m_session_mutex, !m_inbox_mutex);
    int64_t Now() const;

    //! Token-bucket gate for relay fan-out. Returns true (and consumes a token)
    //! if this node may relay another message now; false when the budget is
    //! spent. See Options::relay_tokens_per_sec.
    bool AllowRelay() EXCLUSIVE_LOCKS_REQUIRED(!m_relay_limit_mutex);

    WorkerPool& m_pool;
    BroadcastFn m_broadcast;
    RelayFn m_relay;
    Options m_opts;

    //! Identity + inbox-prekey state, all under one lock because RotatePrekey /
    //! SetIdentity (RPC/scheduler), the pubkey accessors (RPC/net) and HandleJob
    //! (workers) all touch it. Heavy BLS decrypts snapshot the privs under the
    //! lock and run outside it.
    mutable Mutex m_inbox_mutex;
    //! Stable identity: the node's address, and the signer of the prekey.
    blsct::PrivateKey m_identity_priv GUARDED_BY(m_inbox_mutex);
    blsct::PublicKey m_identity_pub GUARDED_BY(m_inbox_mutex);
    //! Current inbox prekey: the actual ECIES target for confidential messages.
    blsct::PrivateKey m_inbox_priv GUARDED_BY(m_inbox_mutex);
    blsct::PublicKey m_inbox_pub GUARDED_BY(m_inbox_mutex);
    //! Identity's signature over m_inbox_pub.GetVch(), published in the bundle.
    blsct::Signature m_prekey_sig GUARDED_BY(m_inbox_mutex);
    //! Recently-retired prekey privs, newest first, kept for a grace window so a
    //! message encrypted to the prekey we just rotated out still decrypts.
    //! Bounded by Options::prekey_grace_keys; entries drop (and their key
    //! material frees) past that, bounding the key-extraction decryption window.
    std::deque<blsct::PrivateKey> m_inbox_prev GUARDED_BY(m_inbox_mutex);
    int64_t m_inbox_rotated_at GUARDED_BY(m_inbox_mutex){0};

    //! Per-request session keys (e.g. RFQ taker reply_keys) trial-decrypted in
    //! addition to the inbox key. Snapshotted under the lock, then used outside
    //! it so heavy BLS decrypts never run while the mutex is held.
    struct SessionKey {
        blsct::PrivateKey priv;
        int64_t expiry; //!< unix seconds; 0 = no auto-expiry
    };
    Mutex m_session_mutex;
    std::vector<std::pair<blsct::PublicKey, SessionKey>> m_session_keys GUARDED_BY(m_session_mutex);

    std::array<MessageHandler, 256> m_handlers{};

    std::atomic<uint64_t> m_pings_received{0};

    Mutex m_replay_mutex;
    CuckooCache::cache<uint256, SignatureCacheHasher> m_replay GUARDED_BY(m_replay_mutex);

    Mutex m_relay_limit_mutex;
    double m_relay_tokens GUARDED_BY(m_relay_limit_mutex){0.0};
    int64_t m_relay_last_refill GUARDED_BY(m_relay_limit_mutex){0};
};

//! Process-wide active transport, set by init when -p2pmsg is enabled and
//! cleared on shutdown. The net thread reads it to dispatch inbound p2pmsg
//! packets. nullptr means the feature is disabled — net code must null-check.
//!
//! These process-global accessors also let the wallet module reach the p2pmsg
//! subsystems: a wallet RPC's request.context is a WalletContext, not a
//! NodeContext, so it cannot use EnsureAnyNodeContext. The subsystems are
//! single-instance per process, so a global handle (set at init, cleared at
//! shutdown) is the clean seam — same pattern the net thread already uses.
void SetActiveTransport(Transport* transport);
Transport* GetActiveTransport();

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_TRANSPORT_H
