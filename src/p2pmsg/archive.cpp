// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/archive.h>

#include <arith_uint256.h>
#include <dbwrapper.h>
#include <hash.h>
#include <logging.h>
#include <streams.h>
#include <util/thread.h>

#include <algorithm>
#include <limits>

namespace p2pmsg {

namespace {

constexpr uint8_t DB_ENV{'e'};
constexpr uint8_t DB_META{'M'};

//! Big-endian so LevelDB's lexicographic order is id order and an iterator
//! walks oldest-first.
struct EnvKey {
    uint64_t id{0};
    EnvKey() = default;
    explicit EnvKey(uint64_t id_in) : id(id_in) {}
    SERIALIZE_METHODS(EnvKey, obj) { READWRITE(Using<BigEndianFormatter<8>>(obj.id)); }
};

struct Meta {
    uint64_t next_id{1};
    uint64_t total_bytes{0};
    uint64_t count{0};
    SERIALIZE_METHODS(Meta, obj) { READWRITE(obj.next_id, obj.total_bytes, obj.count); }
};

} // namespace

uint256 ArchiveStamp::Hash() const
{
    HashWriter hw;
    hw << *this;
    return hw.GetSHA256();
}

uint32_t ArchiveStampBits(uint32_t base_bits, uint32_t scan_budget, uint8_t precision)
{
    // Work asked for is (entries WALKED) x (precision + 2). Charge a doubling
    // of difficulty per doubling of that product over a small free allowance,
    // capped so a legitimate large query stays feasible on a phone.
    //
    // scan_budget rather than limit: limit bounds matches, and a query that
    // matches nothing is the most expensive one there is.
    const uint64_t units = uint64_t{std::max<uint32_t>(scan_budget, 1)} * std::max<uint8_t>(precision, 1);
    const uint64_t free_allowance = 1000 * 4;
    uint32_t extra = 0;
    for (uint64_t u = units; u > free_allowance && extra < 8; u >>= 1) ++extra;
    return base_bits + extra;
}

uint64_t GrindArchiveStamp(ArchiveStamp& stamp, uint32_t bits, uint64_t max_iters)
{
    const arith_uint256 target = TargetFromBits(bits);
    for (uint64_t i = 0; max_iters == 0 || i < max_iters; ++i) {
        stamp.nonce = i;
        if (UintToArith256(stamp.Hash()) <= target) return i + 1;
    }
    return 0;
}

uint256 ArchiveRequest::QueryHash() const
{
    HashWriter hw;
    hw << version << cursor << limit << precision << scan_budget << challenge
       << detection_key << not_before;
    return hw.GetSHA256();
}

EnvelopeArchive::EnvelopeArchive(Options opts) : m_opts(std::move(opts))
{
    LOCK(m_mutex);
    m_db = std::make_unique<CDBWrapper>(DBParams{
        .path = m_opts.path,
        .cache_bytes = size_t{4} << 20,
        .memory_only = m_opts.memory_only,
        .wipe_data = m_opts.wipe,
        // Ciphertext relayed on a public bus, so this is not secret material --
        // but the SET of envelopes a node chose to keep, sitting in .ldb
        // remnants, is still worth the same baseline every other sensitive
        // store gets.
        .obfuscate = true});

    Meta meta;
    if (m_db->Read(DB_META, meta)) {
        m_next_id = meta.next_id;
        m_total_bytes = meta.total_bytes;
        m_count = meta.count;
    }
}

EnvelopeArchive::~EnvelopeArchive() = default;

void EnvelopeArchive::WriteMetaLocked(CDBBatch& batch)
{
    batch.Write(DB_META, Meta{m_next_id, m_total_bytes, m_count});
}

void EnvelopeArchive::PruneLocked(int64_t now, CDBBatch& batch)
{
    // Entries are written in arrival order under a big-endian key, so the
    // oldest are first and a single forward walk serves both caps. Unlike the
    // user inbox there is no priority class here: everything in the archive is
    // opaque ciphertext, so eviction is strictly oldest-first.
    const int64_t cutoff = m_opts.expiry_seconds > 0
                               ? now - m_opts.expiry_seconds
                               : std::numeric_limits<int64_t>::min();
    const bool capped = m_opts.max_total_bytes > 0;

    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    for (it->Seek(std::make_pair(DB_ENV, EnvKey{0})); it->Valid(); it->Next()) {
        std::pair<uint8_t, EnvKey> key;
        if (!it->GetKey(key) || key.first != DB_ENV) break;
        Entry e;
        if (!it->GetValue(e)) break;

        const bool expired = e.received_at < cutoff;
        const bool over_cap = capped && m_total_bytes > m_opts.max_total_bytes;
        // Oldest-first walk: once the head is neither expired nor needed to get
        // back under the cap, nothing behind it can be either.
        if (!expired && !over_cap) break;

        batch.Erase(key);
        m_total_bytes -= std::min<uint64_t>(m_total_bytes, GetSerializeSize(e));
        if (m_count > 0) --m_count;
    }
}

std::optional<uint64_t> EnvelopeArchive::Add(int64_t received_at, uint8_t kind,
                                             std::span<const uint8_t> flag,
                                             std::span<const uint8_t> envelope)
{
    // Unflagged envelopes can never be retrieved, so storing them would be pure
    // cost. This is what keeps the archive proportional to the traffic that
    // actually wants retention rather than to the whole bus.
    if (flag.empty() || envelope.empty()) return std::nullopt;

    LOCK(m_mutex);
    Entry e;
    e.id = m_next_id;
    e.received_at = received_at;
    e.kind = kind;
    e.flag.assign(flag.begin(), flag.end());
    e.envelope.assign(envelope.begin(), envelope.end());

    CDBBatch batch{*m_db};
    batch.Write(std::make_pair(DB_ENV, EnvKey{e.id}), e);
    ++m_next_id;
    m_total_bytes += GetSerializeSize(e);
    ++m_count;
    PruneLocked(received_at, batch);
    WriteMetaLocked(batch);
    if (!m_db->WriteBatch(batch)) {
        LogPrint(BCLog::NET, "p2pmsg: archive write failed\n");
        return std::nullopt;
    }
    return e.id;
}

EnvelopeArchive::ScanResult EnvelopeArchive::Scan(uint64_t cursor,
                                                  std::span<const uint8_t> detection_key,
                                                  size_t max_entries, size_t max_matches,
                                                  size_t max_bytes, int64_t not_before) const
{
    ScanResult out;
    out.next_cursor = cursor;
    LOCK(m_mutex);

    size_t bytes = 0;
    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    // cursor is exclusive, so seek to cursor+1. Guard the wrap: a cursor of
    // UINT64_MAX would otherwise seek to 0 and re-scan the whole store.
    if (cursor == std::numeric_limits<uint64_t>::max()) {
        out.complete = true;
        return out;
    }
    for (it->Seek(std::make_pair(DB_ENV, EnvKey{cursor + 1})); it->Valid(); it->Next()) {
        std::pair<uint8_t, EnvKey> key;
        if (!it->GetKey(key) || key.first != DB_ENV) break;

        if (out.scanned >= max_entries) {
            out.complete = false;
            break;
        }

        Entry e;
        if (!it->GetValue(e)) break;
        ++out.scanned;
        out.next_cursor = e.id;

        // Skipped without testing: narrowing the window is the cheap way for a
        // requester to bound the work it is asking for.
        if (not_before > 0 && e.received_at < not_before) continue;

        // The span is built explicitly: libc++ 14 (the Ubuntu 22.04 CI
        // compiler) ships no std::span range constructor, so a std::vector
        // does not convert on its own.
        if (!FmdTest(detection_key, std::span<const uint8_t>{e.flag.data(), e.flag.size()})) continue;

        const size_t item_bytes = e.envelope.size() + 16;
        if (out.matches.size() >= max_matches || bytes + item_bytes > max_bytes) {
            // This entry matched but does not fit. Do NOT advance past it, or
            // the requester's next cursor would skip a message it matched.
            out.next_cursor = e.id - 1;
            out.complete = false;
            break;
        }
        bytes += item_bytes;
        out.matches.push_back(std::move(e));
    }
    return out;
}

uint64_t EnvelopeArchive::Count() const
{
    LOCK(m_mutex);
    return m_count;
}

uint64_t EnvelopeArchive::TotalBytes() const
{
    LOCK(m_mutex);
    return m_total_bytes;
}

uint64_t EnvelopeArchive::NewestId() const
{
    LOCK(m_mutex);
    return m_next_id > 1 ? m_next_id - 1 : 0;
}

uint64_t EnvelopeArchive::OldestId() const
{
    LOCK(m_mutex);
    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    it->Seek(std::make_pair(DB_ENV, EnvKey{0}));
    std::pair<uint8_t, EnvKey> key;
    if (it->Valid() && it->GetKey(key) && key.first == DB_ENV) return key.second.id;
    return 0;
}

ArchiveScanner::ArchiveScanner(EnvelopeArchive& archive, SendFn send, size_t queue_capacity)
    : m_archive(archive), m_send(std::move(send)),
      m_capacity(queue_capacity == 0 ? DEFAULT_SCAN_QUEUE : queue_capacity)
{
}

ArchiveScanner::~ArchiveScanner()
{
    Stop();
}

void ArchiveScanner::Start()
{
    assert(!m_thread.joinable());
    m_thread = std::thread(&util::TraceThread, "p2pmsgscan", [this] { ThreadLoop(); });
}

void ArchiveScanner::Stop()
{
    {
        LOCK(m_mutex);
        if (m_stopping) return;
        m_stopping = true;
        m_queue.clear();
    }
    m_cv.notify_all();
    if (m_thread.joinable()) m_thread.join();
}

bool ArchiveScanner::Enqueue(PeerId peer, uint64_t cursor, std::vector<uint8_t> detection_key,
                             uint32_t scan_budget, uint16_t limit, int64_t not_before)
{
    {
        LOCK(m_mutex);
        if (m_stopping || m_queue.size() >= m_capacity) return false;
        m_queue.push_back(ScanJob{peer, cursor, std::move(detection_key), scan_budget, limit, not_before});
    }
    m_cv.notify_one();
    return true;
}

size_t ArchiveScanner::QueueDepth() const
{
    LOCK(m_mutex);
    return m_queue.size();
}

size_t ArchiveScanner::DrainForTest()
{
    size_t ran = 0;
    while (true) {
        ScanJob job;
        {
            LOCK(m_mutex);
            if (m_queue.empty()) break;
            job = std::move(m_queue.front());
            m_queue.pop_front();
        }
        RunJob(job);
        ++ran;
    }
    return ran;
}

void ArchiveScanner::ThreadLoop()
{
    while (true) {
        ScanJob job;
        {
            WAIT_LOCK(m_mutex, lock);
            m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                return m_stopping || !m_queue.empty();
            });
            if (m_stopping) return;
            job = std::move(m_queue.front());
            m_queue.pop_front();
        }
        RunJob(job);
    }
}

void ArchiveScanner::RunJob(const ScanJob& job)
{
    const auto scan = m_archive.Scan(
        job.cursor,
        std::span<const uint8_t>{job.detection_key.data(), job.detection_key.size()},
        job.scan_budget, job.limit, MAX_ARCHIVE_RESPONSE_BYTES, job.not_before);

    ArchiveResponse resp;
    resp.next_cursor = scan.next_cursor;
    resp.complete = scan.complete ? 1 : 0;
    resp.items.reserve(scan.matches.size());
    for (const auto& m : scan.matches) {
        resp.items.push_back({m.id, m.received_at, m.envelope});
    }
    if (m_send) m_send(job.peer, std::move(resp), scan.scanned);
}

namespace {
//! Plain atomic pointer; lifetime owned by NodeContext. Net thread only reads.
std::atomic<EnvelopeArchive*> g_active_archive{nullptr};
std::atomic<ArchiveScanner*> g_active_archive_scanner{nullptr};
} // namespace

void SetActiveArchive(EnvelopeArchive* archive)
{
    g_active_archive.store(archive, std::memory_order_release);
}

EnvelopeArchive* GetActiveArchive()
{
    return g_active_archive.load(std::memory_order_acquire);
}

void SetActiveArchiveScanner(ArchiveScanner* scanner)
{
    g_active_archive_scanner.store(scanner, std::memory_order_release);
}

ArchiveScanner* GetActiveArchiveScanner()
{
    return g_active_archive_scanner.load(std::memory_order_acquire);
}

} // namespace p2pmsg
