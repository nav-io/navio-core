// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/user_inbox.h>

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
        .wipe_data = m_opts.wipe});

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
    // Oldest-first walk; each step removes either an over-cap or an expired
    // entry. Stops at the first entry that is both fresh and within budget —
    // entries are stored in arrival order, so nothing later can be older.
    const int64_t cutoff = m_opts.expiry_seconds > 0 ? now - m_opts.expiry_seconds : std::numeric_limits<int64_t>::min();
    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    for (it->Seek(std::make_pair(DB_MSG, MsgKey{0})); it->Valid(); it->Next()) {
        std::pair<uint8_t, MsgKey> key;
        if (!it->GetKey(key) || key.first != DB_MSG) break;
        Entry e;
        if (!it->GetValue(e)) break;
        const bool over_cap = m_opts.max_total_bytes > 0 && m_total_bytes > m_opts.max_total_bytes;
        const bool expired = e.received_at < cutoff;
        if (!over_cap && !expired) break;
        batch.Erase(key);
        const size_t sz = EntryBytes(e);
        m_total_bytes -= std::min<uint64_t>(m_total_bytes, sz);
        if (m_count > 0) --m_count;
    }
}

std::optional<UserInbox::Entry> UserInbox::Add(int64_t received_at, MsgScope scope, const std::string& topic,
                                               const blsct::PublicKey& sender_session, std::vector<uint8_t> body)
{
    LOCK(m_mutex);
    Entry e;
    e.id = m_next_id;
    e.received_at = received_at;
    e.scope = static_cast<uint8_t>(scope);
    e.topic = topic;
    e.sender_session = sender_session.GetVch();
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
        m_db->WriteBatch(batch, /*fSync=*/false);
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
    m_db->WriteBatch(batch, /*fSync=*/false);
    return true;
}

bool UserInbox::Unsubscribe(const std::string& topic)
{
    LOCK(m_mutex);
    if (m_topics.erase(topic) == 0) return false;
    CDBBatch batch{*m_db};
    WriteTopicsLocked(batch);
    m_db->WriteBatch(batch, /*fSync=*/false);
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
