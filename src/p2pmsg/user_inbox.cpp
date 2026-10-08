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

//! An entry's budget. An unknown scope byte counts as inbox, the scope
//! listp2pmsgs reports it under.
size_t ScopeIndex(uint8_t scope)
{
    return scope < NUM_MSG_SCOPES ? scope : static_cast<size_t>(MsgScope::INBOX);
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

    // m_scope_bytes is not persisted (see its declaration): count it here.
    LOCK(m_mutex);
    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    for (it->Seek(std::make_pair(DB_MSG, MsgKey{0})); it->Valid(); it->Next()) {
        std::pair<uint8_t, MsgKey> key;
        if (!it->GetKey(key) || key.first != DB_MSG) break;
        Entry e;
        if (!it->GetValue(e)) break;
        m_scope_bytes[ScopeIndex(e.scope)] += EntryBytes(e);
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

uint64_t UserInbox::ScopeCapBytes(size_t max_total_bytes, MsgScope scope)
{
    unsigned percent{0};
    switch (scope) {
    case MsgScope::INBOX: percent = USER_STORE_INBOX_PERCENT; break;
    case MsgScope::BROADCAST: percent = USER_STORE_BROADCAST_PERCENT; break;
    case MsgScope::SESSION: percent = USER_STORE_SESSION_PERCENT; break;
    }
    // Split before multiplying so a cap near SIZE_MAX cannot overflow.
    const uint64_t max{max_total_bytes};
    return max / 100 * percent + max % 100 * percent / 100;
}

void UserInbox::ForgetLocked(uint8_t scope, uint64_t bytes)
{
    m_total_bytes -= std::min(m_total_bytes, bytes);
    uint64_t& scope_bytes = m_scope_bytes[ScopeIndex(scope)];
    scope_bytes -= std::min(scope_bytes, bytes);
    if (m_count > 0) --m_count;
}

void UserInbox::PruneLocked(int64_t now, CDBBatch& batch)
{
    const int64_t cutoff = m_opts.expiry_seconds > 0 ? now - m_opts.expiry_seconds : std::numeric_limits<int64_t>::min();
    std::array<uint64_t, NUM_MSG_SCOPES> cap{};
    for (size_t sc = 0; sc < NUM_MSG_SCOPES; ++sc) {
        cap[sc] = ScopeCapBytes(m_opts.max_total_bytes, static_cast<MsgScope>(sc));
    }
    const auto over_budget = [&](size_t sc) EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        return m_opts.max_total_bytes > 0 && m_scope_bytes[sc] > cap[sc];
    };
    const auto any_over_budget = [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        for (size_t sc = 0; sc < NUM_MSG_SCOPES; ++sc) {
            if (over_budget(sc)) return true;
        }
        return false;
    };
    if (m_opts.expiry_seconds <= 0 && !any_over_budget()) return;

    // One walk, oldest first (big-endian MsgKey is arrival order): drop every
    // expired entry, and the oldest entries of each scope over its budget --
    // never another scope's. It stops at the first fresh entry once every
    // scope is within budget, since nothing older remains to expire; within
    // budget that keeps the cost O(expired), not O(store), which is what
    // keeps per-message cost bounded by PoW. Each key is visited once: the
    // iterator reads the backing store, NOT the pending batch, so a second
    // walk would see these erasures again and double-subtract them from the
    // totals -- persisted into DB_META, that undercount permanently disarms
    // the size cap.
    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    for (it->Seek(std::make_pair(DB_MSG, MsgKey{0})); it->Valid(); it->Next()) {
        std::pair<uint8_t, MsgKey> key;
        if (!it->GetKey(key) || key.first != DB_MSG) break;
        Entry e;
        if (!it->GetValue(e)) break;
        const bool expired = e.received_at < cutoff;
        if (!expired && !any_over_budget()) break;
        if (!expired && !over_budget(ScopeIndex(e.scope))) continue;
        batch.Erase(key);
        ForgetLocked(e.scope, EntryBytes(e));
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
    m_scope_bytes[ScopeIndex(e.scope)] += EntryBytes(e);
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
        ForgetLocked(e.scope, EntryBytes(e));
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
