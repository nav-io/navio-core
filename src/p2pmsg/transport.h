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

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace p2pmsg {

//! Application payload tag carried inside the encrypted terminal layer.
enum class PayloadKind : uint8_t {
    PING = 0,
    PONG = 1,
    AGG_ANN = 2,
    CANDIDATE_TX = 3,
    RFQ_REQ = 4,
    RFQ_QUOTE = 5,
    ORDER_ANN = 6,
};

//! True for request kinds that must carry a PoW stamp.
bool KindRequiresPoW(PayloadKind kind);

//! The wire envelope for a `p2pmsg`/`dp2pmsg` net message:
//!   u8 kind || optional PoWHeader (for stamped kinds) || EciesPacket
//! The PoW header's payload_hash binds the ciphertext, so the cheap net-thread
//! PoW check also gates the (expensive) decrypt that follows on a worker.
struct Envelope {
    uint8_t kind{0};
    bool has_pow{false};
    PoWHeader pow;
    EciesPacket enc;

    SERIALIZE_METHODS(Envelope, obj)
    {
        READWRITE(obj.kind, obj.has_pow);
        if (obj.has_pow) READWRITE(obj.pow);
        READWRITE(obj.enc);
    }
};

//! Sends a serialized envelope to one peer (fluff) or the stem successor.
//! `stem` selects the Dandelion phase. Implemented by the net layer.
using SendFn = std::function<void(int64_t to_peer, bool stem, const Envelope&)>;
//! Broadcasts a fresh envelope to the stem successor (Dandelion) or, if no stem
//! route exists, to all relay peers.
using BroadcastFn = std::function<void(bool stem, const Envelope&)>;

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

    Transport(WorkerPool& pool, SendFn send, BroadcastFn broadcast, Options opts);
    Transport(WorkerPool& pool, SendFn send, BroadcastFn broadcast)
        : Transport(pool, std::move(send), std::move(broadcast), Options{}) {}

    //! Our inbox key: peers encrypt to this; we decrypt inbound with it.
    const blsct::PublicKey& InboxPubKey() const { return m_inbox_pub; }

    //! Register the handler for an application kind. Call before the net is live.
    void RegisterHandler(PayloadKind kind, MessageHandler handler);

    //! Net-thread entrypoint. `stem` = arrived as dp2pmsg. Parses the envelope,
    //! verifies PoW (stamped kinds) + replay, then enqueues a decrypt job.
    //! Returns false (with a misbehavior hint) on clearly invalid input.
    enum class WireResult { Enqueued, RejectInvalid, RejectPoW, RejectReplay, Dropped };
    WireResult OnWire(int64_t from_peer, bool stem, std::span<const uint8_t> body)
        EXCLUSIVE_LOCKS_REQUIRED(!m_replay_mutex);

    //! Build + encrypt + (PoW-stamp if required) + broadcast an outbound message
    //! to `recipient`'s session key. Heavy; call off the net thread.
    void Send(const blsct::PublicKey& recipient, PayloadKind kind,
              std::vector<uint8_t> body, bool stem);

    int64_t now_override{0}; //!< test hook: if non-zero, used as "now"

private:
    //! Decrypt + dispatch one enqueued job. Runs on a worker thread; touches no
    //! shared state guarded by m_replay_mutex.
    void HandleJob(const Job& job);
    int64_t Now() const;

    WorkerPool& m_pool;
    SendFn m_send;
    BroadcastFn m_broadcast;
    Options m_opts;

    blsct::PrivateKey m_inbox_priv;
    blsct::PublicKey m_inbox_pub;

    std::array<MessageHandler, 256> m_handlers{};

    Mutex m_replay_mutex;
    CuckooCache::cache<uint256, SignatureCacheHasher> m_replay GUARDED_BY(m_replay_mutex);
};

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_TRANSPORT_H
