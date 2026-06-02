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
#include <functional>
#include <optional>
#include <vector>

namespace p2pmsg {

//! Whether the p2p messaging subsystem is enabled by default. Off until the
//! feature set (aggregation, RFQ, standing orders) lands and is integration-tested.
static constexpr bool DEFAULT_P2PMSG_ENABLE{false};

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

//! Sends a serialized envelope to one peer (fluff) or the stem successor.
//! `stem` selects the Dandelion phase. Implemented by the net layer.
using SendFn = std::function<void(int64_t to_peer, bool stem, const Envelope&)>;
//! Broadcasts a fresh envelope to the stem successor (Dandelion) or, if no stem
//! route exists, to all relay peers.
using BroadcastFn = std::function<void(bool stem, const Envelope&)>;
//! Relay an already-received envelope to all peers EXCEPT its origin, so it
//! floods the network. Kind-blind: called for every new valid message whether
//! or not this node understands or can decrypt it.
using RelayFn = std::function<void(int64_t origin_peer, bool stem, const Envelope&)>;

//! Decrypted, authenticated inbound message handed to a feature module.
struct InboundMessage {
    PayloadKind kind;
    int64_t from_peer;
    blsct::PublicKey sender_session; //!< the envelope's ephemeral pubkey
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
    };

    Transport(WorkerPool& pool, SendFn send, BroadcastFn broadcast, RelayFn relay, Options opts);
    Transport(WorkerPool& pool, SendFn send, BroadcastFn broadcast, RelayFn relay)
        : Transport(pool, std::move(send), std::move(broadcast), std::move(relay), Options{}) {}

    //! Our inbox key: peers encrypt to this; we decrypt inbound with it.
    const blsct::PublicKey& InboxPubKey() const { return m_inbox_pub; }

    //! Register the handler for an application kind. Call before the net is live.
    void RegisterHandler(PayloadKind kind, MessageHandler handler);

    //! Net-thread entrypoint. `stem` = arrived as dp2pmsg. Parses the envelope,
    //! verifies the mandatory PoW + timestamp, checks the replay cache. If the
    //! message is new and valid it is RELAYED to all other peers (kind-blind, so
    //! the bus carries apps this node does not implement) and a decrypt job is
    //! enqueued for our own handlers. Returns the disposition.
    enum class WireResult { Enqueued, RejectInvalid, RejectPoW, RejectReplay, Dropped };
    WireResult OnWire(int64_t from_peer, bool stem, std::span<const uint8_t> body)
        EXCLUSIVE_LOCKS_REQUIRED(!m_replay_mutex);

    //! Build + encrypt + PoW-stamp + broadcast an outbound message to
    //! `recipient`'s session key. PoW is always applied. Heavy; call off the net
    //! thread.
    void Send(const blsct::PublicKey& recipient, PayloadKind kind,
              std::vector<uint8_t> body, bool stem);

    //! Total PING payloads decrypted+dispatched to us. Debug/observability.
    uint64_t PingsReceived() const { return m_pings_received.load(std::memory_order_relaxed); }

    int64_t now_override{0}; //!< test hook: if non-zero, used as "now"

private:
    //! Decrypt + dispatch one enqueued job. Runs on a worker thread; touches no
    //! shared state guarded by m_replay_mutex.
    void HandleJob(const Job& job);
    int64_t Now() const;

    WorkerPool& m_pool;
    SendFn m_send;
    BroadcastFn m_broadcast;
    RelayFn m_relay;
    Options m_opts;

    blsct::PrivateKey m_inbox_priv;
    blsct::PublicKey m_inbox_pub;

    std::array<MessageHandler, 256> m_handlers{};

    std::atomic<uint64_t> m_pings_received{0};

    Mutex m_replay_mutex;
    CuckooCache::cache<uint256, SignatureCacheHasher> m_replay GUARDED_BY(m_replay_mutex);
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
