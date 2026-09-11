// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/user_inbox.h>

#include <util/time.h>

#include <dbwrapper.h>
#include <logging.h>

namespace p2pmsg {

namespace {

constexpr uint8_t DB_MSG{'m'};
constexpr uint8_t DB_META{'M'};
constexpr uint8_t DB_TOPICS{'S'};

//! Message keys serialize the id BIG-endian so LevelDB's lexicographic key
//! order is id order and an iterator Seek walks messages oldest-first.
struct MsgKey {
    uint64_t id{0};
    MsgKey() = default;
    explicit MsgKey(uint64_t id_in) : id(id_in) {}
    SERIALIZE_METHODS(MsgKey, obj) { READWRITE(Using<BigEndianFormatter<8>>(obj.id)); }
};

struct Meta {
    uint64_t next_id{1};
    uint64_t total_bytes{0};
    uint64_t count{0};
    SERIALIZE_METHODS(Meta, obj) { READWRITE(obj.next_id, obj.total_bytes, obj.count); }
};

size_t EntryBytes(const UserInbox::Entry& e)
{
    return GetSerializeSize(e);
}

} // namespace

UserInbox::UserInbox(Options opts) : m_opts(std::move(opts))
{
    m_db = std::make_unique<CDBWrapper>(DBParams{
        .path = m_opts.path,
        .cache_bytes = size_t{2} << 20,
        .memory_only = m_opts.memory_only,
        .wipe_data = m_opts.wipe,
        // Private message payloads: obfuscate like the wallet's databases so
        // cleared entries and .log/.ldb remnants are not grep-able plaintext
        // at rest. (Not encryption -- an at-rest guarantee needs full-disk
        // crypto -- but the same baseline every other sensitive store gets.)
        .obfuscate = true});

    Meta meta;
    if (m_db->Read(DB_META, meta)) {
        m_next_id = meta.next_id;
        m_total_bytes = meta.total_bytes;
        m_count = meta.count;
    }
    std::vector<std::string> topics;
    if (m_db->Read(DB_TOPICS, topics)) {
        m_topics.insert(topics.begin(), topics.end());
    }
}

UserInbox::~UserInbox() = default;

void UserInbox::WriteMetaLocked(CDBBatch& batch)
{
    batch.Write(DB_META, Meta{m_next_id, m_total_bytes, m_count});
}

void UserInbox::WriteTopicsLocked(CDBBatch& batch)
{
    batch.Write(DB_TOPICS, std::vector<std::string>{m_topics.begin(), m_topics.end()});
}

void UserInbox::PruneLocked(int64_t now, CDBBatch& batch)
{
    // Single scan: the DB iterator reads the backing store, NOT the pending
    // batch, so a two-pass walk would see pass-1 erasures again in pass 2 and
    // double-subtract them from m_total_bytes/m_count -- persisted into
    // DB_META, that undercount permanently disarms the size cap. Collect the
    // metadata once, decide, erase each key exactly once.
    struct Candidate {
        std::pair<uint8_t, MsgKey> key;
        size_t bytes;
        bool expired;
        bool broadcast;
    };
    const int64_t cutoff = m_opts.expiry_seconds > 0 ? now - m_opts.expiry_seconds : std::numeric_limits<int64_t>::min();
    // Cheap path: within the size cap, only expiry can evict. Entries are
    // stored in arrival order (big-endian MsgKey), so the oldest are first and
    // the scan can stop at the first non-expired one -- O(expired), not
    // O(store), which is what keeps per-message cost bounded by PoW. Only the
    // over-cap case needs the full collect-and-decide walk below (its
    // broadcast-first eviction can't early-exit). No expiry configured + within
    // cap: nothing to do at all.
    const bool over_cap = m_opts.max_total_bytes > 0 && m_total_bytes > m_opts.max_total_bytes;
    if (!over_cap) {
        if (m_opts.expiry_seconds <= 0) return;
        std::unique_ptr<CDBIterator> eit{m_db->NewIterator()};
        for (eit->Seek(std::make_pair(DB_MSG, MsgKey{0})); eit->Valid(); eit->Next()) {
            std::pair<uint8_t, MsgKey> key;
            if (!eit->GetKey(key) || key.first != DB_MSG) break;
            Entry e;
            if (!eit->GetValue(e)) break;
            if (e.received_at >= cutoff) break; // first fresh entry: nothing older remains
            batch.Erase(key);
            m_total_bytes -= std::min<uint64_t>(m_total_bytes, EntryBytes(e));
            if (m_count > 0) --m_count;
        }
        return;
    }

    std::vector<Candidate> entries;
    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    for (it->Seek(std::make_pair(DB_MSG, MsgKey{0})); it->Valid(); it->Next()) {
        std::pair<uint8_t, MsgKey> key;
        if (!it->GetKey(key) || key.first != DB_MSG) break;
        Entry e;
        if (!it->GetValue(e)) break;
        entries.push_back({key, EntryBytes(e), e.received_at < cutoff,
                           e.scope == static_cast<uint8_t>(MsgScope::BROADCAST)});
    }

    std::vector<bool> erase(entries.size(), false);
    uint64_t remaining = m_total_bytes;
    // Expiry applies to everything.
    for (size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].expired) {
            erase[i] = true;
            remaining -= std::min<uint64_t>(remaining, entries[i].bytes);
        }
    }
    // Size cap: broadcast-scope first (a public-topic flood must not push out
    // unread 1:1 messages), then oldest-first across the rest.
    if (m_opts.max_total_bytes > 0) {
        for (const bool broadcast_only : {true, false}) {
            for (size_t i = 0; i < entries.size() && remaining > m_opts.max_total_bytes; ++i) {
                if (erase[i]) continue;
                if (broadcast_only && !entries[i].broadcast) continue;
                erase[i] = true;
                remaining -= std::min<uint64_t>(remaining, entries[i].bytes);
            }
        }
    }
    for (size_t i = 0; i < entries.size(); ++i) {
        if (!erase[i]) continue;
        batch.Erase(entries[i].key);
        m_total_bytes -= std::min<uint64_t>(m_total_bytes, entries[i].bytes);
        if (m_count > 0) --m_count;
    }
}

std::optional<UserInbox::Entry> UserInbox::Add(int64_t received_at, MsgScope scope, const std::string& topic,
                                               const blsct::PublicKey& sender_session, std::vector<uint8_t> body,
                                               const std::vector<uint8_t>& reply_pubkey)
{
    LOCK(m_mutex);
    Entry e;
    e.id = m_next_id;
    e.received_at = received_at;
    e.scope = static_cast<uint8_t>(scope);
    e.topic = topic;
    e.sender_session = sender_session.GetVch();
    e.reply_pubkey = reply_pubkey;
    e.payload = std::move(body);

    CDBBatch batch{*m_db};
    batch.Write(std::make_pair(DB_MSG, MsgKey{e.id}), e);
    ++m_next_id;
    m_total_bytes += EntryBytes(e);
    ++m_count;
    PruneLocked(received_at, batch);
    WriteMetaLocked(batch);
    if (!m_db->WriteBatch(batch, /*fSync=*/false)) {
        LogPrintf("p2pmsg: user inbox write failed (id=%d)\n", e.id);
        return std::nullopt;
    }
    return e;
}

std::vector<UserInbox::Entry> UserInbox::List(uint64_t since_id, size_t max_count, const std::string& topic) const
{
    LOCK(m_mutex);
    std::vector<Entry> out;
    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    for (it->Seek(std::make_pair(DB_MSG, MsgKey{since_id + 1})); it->Valid(); it->Next()) {
        std::pair<uint8_t, MsgKey> key;
        if (!it->GetKey(key) || key.first != DB_MSG) break;
        Entry e;
        if (!it->GetValue(e)) break;
        if (!topic.empty() && e.topic != topic) continue;
        // Expiry is enforced on writes (PruneLocked runs in Add); with no new
        // traffic, expired entries linger on disk until then -- skip them
        // here so they at least stop being SERVED past their expiry.
        if (m_opts.expiry_seconds > 0 && e.received_at < GetTime<std::chrono::seconds>().count() - m_opts.expiry_seconds) continue;
        out.push_back(std::move(e));
        if (max_count != 0 && out.size() >= max_count) break;
    }
    return out;
}

size_t UserInbox::Clear(uint64_t up_to_id)
{
    LOCK(m_mutex);
    size_t removed = 0;
    CDBBatch batch{*m_db};
    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    for (it->Seek(std::make_pair(DB_MSG, MsgKey{0})); it->Valid(); it->Next()) {
        std::pair<uint8_t, MsgKey> key;
        if (!it->GetKey(key) || key.first != DB_MSG) break;
        if (up_to_id != 0 && key.second.id > up_to_id) break;
        Entry e;
        if (!it->GetValue(e)) break;
        batch.Erase(key);
        const size_t sz = EntryBytes(e);
        m_total_bytes -= std::min<uint64_t>(m_total_bytes, sz);
        if (m_count > 0) --m_count;
        ++removed;
    }
    if (removed > 0) {
        WriteMetaLocked(batch);
        if (!m_db->WriteBatch(batch, /*fSync=*/true)) {
            // "Delete my messages" must not report success while the disk
            // still holds them (they would resurrect on restart).
            throw std::runtime_error("p2pmsg: user inbox clear failed to persist");
        }
    }
    return removed;
}

size_t UserInbox::Size() const
{
    LOCK(m_mutex);
    return m_count;
}

uint64_t UserInbox::TotalBytes() const
{
    LOCK(m_mutex);
    return m_total_bytes;
}

uint64_t UserInbox::LastId() const
{
    LOCK(m_mutex);
    return m_next_id - 1;
}

bool UserInbox::Subscribe(const std::string& topic)
{
    LOCK(m_mutex);
    if (!m_topics.insert(topic).second) return false;
    CDBBatch batch{*m_db};
    WriteTopicsLocked(batch);
    if (!m_db->WriteBatch(batch, /*fSync=*/false)) {
        m_topics.erase(topic); // keep memory and disk consistent
        return false;
    }
    return true;
}

bool UserInbox::Unsubscribe(const std::string& topic)
{
    LOCK(m_mutex);
    if (m_topics.erase(topic) == 0) return false;
    CDBBatch batch{*m_db};
    WriteTopicsLocked(batch);
    if (!m_db->WriteBatch(batch, /*fSync=*/false)) {
        m_topics.insert(topic); // keep memory and disk consistent
        return false;
    }
    return true;
}

bool UserInbox::IsSubscribed(const std::string& topic) const
{
    LOCK(m_mutex);
    return m_topics.contains(topic);
}

std::vector<std::string> UserInbox::Topics() const
{
    LOCK(m_mutex);
    return {m_topics.begin(), m_topics.end()};
}

} // namespace p2pmsg
