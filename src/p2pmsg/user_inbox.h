// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_USER_INBOX_H
#define BITCOIN_P2PMSG_USER_INBOX_H

#include <blsct/public_key.h>
#include <serialize.h>
#include <sync.h>
#include <util/fs.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

class CDBWrapper;
class CDBBatch;

namespace p2pmsg {

//! Ceiling on a serialized USER_DATA frame (topic + body) accepted for send.
//! The whole wire envelope (kind byte + PoW header + ECIES packet) must fit
//! the worker-pool job buffer (MAX_JOB_BYTES = 4096); the fixed envelope
//! overhead is ~170 bytes, so this leaves comfortable headroom. Applications
//! needing more chunk at the application layer and reassemble on receive.
static constexpr size_t MAX_USER_MSG_BYTES = 3584;

//! Ceiling on the frame's topic string. The topic is the pub/sub routing key
//! for broadcast messages and the store's filter column; it is not content.
static constexpr size_t MAX_USER_MSG_TOPIC_BYTES = 64;

//! Defaults for the on-disk store's growth bounds (-p2pmsgstoresize MiB,
//! -p2pmsgstoreexpiry days).
static constexpr uint64_t DEFAULT_USER_STORE_MB = 64;
static constexpr uint64_t DEFAULT_USER_STORE_EXPIRY_DAYS = 30;

//! Which local key class delivered a stored message. Mirrors
//! transport RecipientKey but is part of the STORE's persisted schema, so it
//! is its own enum: the transport enum can evolve without rewriting disk.
enum class MsgScope : uint8_t {
    INBOX = 0,     //!< encrypted 1:1 to our rotating inbox prekey
    BROADCAST = 1, //!< readable by anyone; stored because the topic is subscribed
    SESSION = 2,   //!< encrypted to a reply key minted via mintp2pmsgreplykey
};

//! The node-parsed framing inside a USER_DATA payload: a routing topic plus an
//! opaque body. The topic is the ONLY part the node interprets — it keys
//! broadcast subscriptions and store filtering. Everything an application
//! needs beyond that (sender identity, reply key, threading, content type) is
//! application framing inside `body`.
struct UserMsgFrame {
    std::string topic;
    std::vector<uint8_t> body;

    SERIALIZE_METHODS(UserMsgFrame, obj)
    {
        READWRITE(obj.topic, obj.body);
    }
};

//! On-disk store for inbound USER_DATA messages, drained over RPC
//! (listp2pmsgs/clearp2pmsgs) and pushed via ZMQ / -p2pmsgnotify.
//!
//! LevelDB-backed so an application that polls infrequently (or a node that
//! restarts) does not lose messages. Growth is bounded two ways, both
//! enforced on insert: a total-bytes cap (-p2pmsgstoresize) pruning OLDEST
//! first, and an age cap (-p2pmsgstoreexpiry). Message ids increase
//! monotonically for the life of the store and never repeat, so a client
//! polls with `since_id` and misses nothing that was not pruned.
//!
//! Broadcast subscriptions live here too (persisted): a broadcast USER_DATA
//! is only stored when its topic is subscribed; 1:1 inbox and session-keyed
//! messages are always stored.
class UserInbox
{
public:
    struct Options {
        fs::path path;
        size_t max_total_bytes{64 * 1024 * 1024};
        int64_t expiry_seconds{30 * 24 * 3600};
        bool memory_only{false}; //!< tests
        bool wipe{false};
    };

    struct Entry {
        uint64_t id{0};
        int64_t received_at{0}; //!< unix seconds, local clock
        uint8_t scope{0};       //!< MsgScope
        std::string topic;
        std::vector<uint8_t> sender_session; //!< envelope ephemeral pubkey (not a reply address)
        std::vector<uint8_t> payload;        //!< the frame's opaque body

        SERIALIZE_METHODS(Entry, obj)
        {
            READWRITE(obj.id, obj.received_at, obj.scope, obj.topic, obj.sender_session, obj.payload);
        }
    };

    explicit UserInbox(Options opts);
    ~UserInbox();

    //! Store an inbound message, pruning oldest/expired entries to keep the
    //! caps. Returns the stored entry (with its assigned id) so callers can
    //! feed push notifiers, or std::nullopt if the write failed.
    std::optional<Entry> Add(int64_t received_at, MsgScope scope, const std::string& topic,
                             const blsct::PublicKey& sender_session, std::vector<uint8_t> body)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Entries with id > since_id, oldest first, at most max_count (0 = all).
    //! Empty topic = no topic filter.
    std::vector<Entry> List(uint64_t since_id, size_t max_count, const std::string& topic) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Drop every entry with id <= up_to_id (0 = drop all). Returns the number
    //! of entries removed.
    size_t Clear(uint64_t up_to_id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    uint64_t TotalBytes() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! The id the NEXT stored message will get minus one; a client records
    //! this as its starting cursor to receive only messages from now on.
    uint64_t LastId() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Broadcast-topic subscriptions (persisted). Returns false when already
    //! (un)subscribed.
    bool Subscribe(const std::string& topic) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool Unsubscribe(const std::string& topic) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool IsSubscribed(const std::string& topic) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::vector<std::string> Topics() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    mutable Mutex m_mutex;
    const Options m_opts;
    std::unique_ptr<CDBWrapper> m_db;
    uint64_t m_next_id GUARDED_BY(m_mutex){1};
    uint64_t m_total_bytes GUARDED_BY(m_mutex){0};
    uint64_t m_count GUARDED_BY(m_mutex){0};
    std::set<std::string> m_topics GUARDED_BY(m_mutex);

    void WriteMetaLocked(CDBBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void WriteTopicsLocked(CDBBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    //! Delete oldest entries until both caps hold. Adds deletes to `batch`
    //! and updates the cached totals.
    void PruneLocked(int64_t now, CDBBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
};

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_USER_INBOX_H
